import { readFileSync } from "fs";
import ssh2, { Server as SSH2Server } from "ssh2";
import { timingSafeEqual } from "crypto";
import { ParsedKey } from "ssh2-streams";
import log from "~/log";
import ContainerManager from "./container-manager";
import internal from "stream";

function checkValue(input: Buffer, allowed: Buffer): boolean {
  const autoReject = input.length !== allowed.length;
  if (autoReject) {
    // Prevent leaking length information by always making a comparison with the
    // same input when lengths don't match what we expect ...
    allowed = input;
  }
  const isMatch = timingSafeEqual(
    new Uint8Array(input),
    new Uint8Array(allowed)
  );
  return !autoReject && isMatch;
}

export default class SSHServer {
  private readonly server: SSH2Server;
  constructor(
    hostFilePath: string,
    private readonly port: number,
    private readonly containers: ContainerManager
  ) {
    this.server = new SSH2Server({
      hostKeys: [readFileSync(hostFilePath)],
    });

    this.server.on("connection", (client, info) => {
      this.connectionHandler(client, info);
    });

    this.server.listen(port, () => {
      log.info(`SSH Server listening on ${port}`);
    });
  }

  private async authenticationHandler(
    client: ssh2.Connection,
    context: ssh2.AuthContext
  ): Promise<void> {
    const reject = () => {
      log.info("Rejecting authentication");
      context.reject(["publickey"]);
    };

    const isLogs = context.username.startsWith("logs.");
    const username = isLogs ? context.username.substring(5) : context.username;

    try {
      log.info(
        { username, method: context.method },
        "SSH Authentication Started"
      );

      if (context.method !== "publickey") {
        log.info(`Rejecting non-publickey auth attempt: ${context.method}`);
        return reject();
      }

      log.info({ key: context.key }, "Received public key from client");

      const config = await this.containers.resolveConfig(username);
      if (config === undefined) {
        log.info("No config found for username");
        return reject();
      }

      const allowedKeys = config.ssh_keys
        .map((key) => {
          const parsed = ssh2.utils.parseKey(key);
          log.info({ key, parsed: !!parsed }, "Parsing configured key");
          return parsed;
        })
        .filter((key): key is ParsedKey => key !== undefined);

      log.info(`Found ${allowedKeys.length} valid keys in config`);

      if (allowedKeys.length <= 0) {
        log.info("No valid keys found in config");
        return reject();
      }

      if (context.method === "publickey") {
        let valid = false;
        for (const key of allowedKeys) {
          log.info(
            {
              clientAlgo: context.key.algo,
              configAlgo: key.type,
              matches: context.key.algo === key.type,
            },
            "Checking key algorithm"
          );

          log.info(
            {
              clientKey: context.key.data.toString("base64"),
              configKey: key.getPublicSSH().toString(),
              clientKeyLength: context.key.data.length,
              configKeyLength: key.getPublicSSH().length,
            },
            "Key comparison details"
          );

          // Remove any whitespace or newlines from the key
          const cleanKey = key.getPublicSSH().toString().replace(/\s+/g, "");
          const cleanClientKey = context.key.data
            .toString("base64")
            .replace(/\s+/g, "");

          const keyMatches = cleanKey === cleanClientKey;
          log.info({ keyMatches }, "Key match result");

          if (context.signature) {
            const signatureValid = key.verify(context.blob, context.signature);
            log.info({ signatureValid }, "Checking signature");
          }

          if (
            context.key.algo === key.type &&
            keyMatches &&
            (!context.signature ||
              key.verify(context.blob, context.signature) === true)
          ) {
            valid = true;
            log.info("Found matching valid key");
            break;
          }
        }
        if (!valid) {
          log.info("No matching valid key found");
          return reject();
        }
      }

      log.info("SSH Authentication Successful");

      client.on("session", (accept, reject) => {
        this.sessionHandler(client, accept, reject, username, isLogs);
      });

      context.accept();
    } catch (e) {
      log.error("Authentication error:", e);
      reject();
    }
  }

  private async sessionHandler(
    client: ssh2.Connection,
    acceptSess: () => ssh2.Session,
    rejectSess: () => void,
    username: string,
    isLogs: boolean
  ): Promise<void> {
    log.info({ username, isLogs }, "SSH Session requested");
    try {
      log.info("SSH Session Started");
      const container = await this.containers.resolveContainer(username);
      if (container === undefined) return rejectSess();

      if (isLogs) {
        log.debug("log session");
        const containerStream = await container.logs({
          stderr: true,
          stdout: true,
          follow: true,
          tail: 100,
        });

        const session = acceptSess();

        if (!session) {
          throw new Error("Session is undefined");
        }
        session.on("pty", (accept: () => void, reject: () => void) => {
          log.debug("pty requested");
          accept();
        });

        session.on(
          "shell",
          (accept: () => ssh2.ServerChannel, reject: () => void) => {
            log.debug("shell requested");
            try {
              log.info("SSH Log session started");
              const stream = accept();
              const sessionStream = new internal.PassThrough();

              sessionStream.on("data", (data) => {
                stream.write(data);
              });

              container.modem.demuxStream(
                containerStream,
                sessionStream,
                sessionStream
              );

              containerStream.on("end", () => {
                stream.end();
                client.end();
              });

              stream.on("error", (err: any) => {
                log.error("Stream error:", err);
                client.end();
              });
            } catch (e) {
              log.error("Shell error:", e);
              reject();
            }
          }
        );
      } else {
        const exec = await container.exec({
          Cmd: ["/bin/bash"],
          AttachStderr: true,
          AttachStdout: true,
          AttachStdin: true,
          Tty: true,
        });

        const containerStream = await exec.start({
          hijack: true,
          stdin: true,
          Tty: true,
        });

        const session = acceptSess();
        if (!session) {
          throw new Error("Session is undefined");
        }
        session.on("pty", (accept: () => void, reject: () => void) => {
          accept();
        });

        session.on(
          "shell",
          (accept: () => ssh2.ServerChannel, reject: () => void) => {
            try {
              log.info("SSH Shell started");
              const stream = accept();

              stream.on("error", (err: any) => {
                log.error("Stream error:", err);
                client.end();
              });

              containerStream.on("error", (err) => {
                log.error("Container stream error:", err);
                client.end();
              });

              container.modem.demuxStream(containerStream, stream, stream);

              containerStream.on("end", () => {
                stream.end();
                client.end();
              });

              containerStream.pipe(stream);
              stream.pipe(containerStream);
            } catch (e) {
              log.error("Shell error:", e);
              reject();
            }
          }
        );
      }
    } catch (e) {
      log.error("Session error:", e);
      rejectSess();
    }
  }

  private connectionHandler(
    client: ssh2.Connection,
    info: ssh2.ClientInfo
  ): void {
    client.on("authentication", (context) =>
      this.authenticationHandler(client, context)
    );

    client.on("error", (err) => {
      log.error("Client connection error:", err);
    });
  }
}
