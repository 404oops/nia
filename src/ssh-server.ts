import { readFileSync } from "fs";
import ssh2, { Server as SSH2Server } from "ssh2";
import { timingSafeEqual } from "crypto";
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
    context: ssh2.PublicKeyAuthContext
  ): Promise<void> {
    try {
      log.info(
        {
          username: context.username,
          method: context.method,
          keyType: context.key?.algo,
          hasSignature: !!context.signature,
          keyData: context.key?.data.toString("base64"),
          keyAlgo: context.key?.algo,
        },
        "Auth attempt"
      );

      if (context.method !== "publickey") {
        return context.reject(["publickey"]);
      }

      const config = await this.containers.resolveConfig(context.username);
      if (!config) {
        return context.reject();
        log.error("No config found for user");
      }

      // First phase: key check
      if (!context.signature) {
        return context.accept();
      }

      // Second phase: signature verification
      for (const configuredKeyStr of config.ssh_keys) {
        const parsedKey = ssh2.utils.parseKey(configuredKeyStr);
        if (!parsedKey || parsedKey instanceof Error) {
          log.warn(
            { error: parsedKey, keyStr: configuredKeyStr },
            "Failed to parse configured key"
          );
          continue;
        }
        const key = Array.isArray(parsedKey) ? parsedKey[0] : parsedKey;

        // Check key algorithm and raw public key data first
        if (
          context.key?.algo !== key.type ||
          !checkValue(
            context.key?.data,
            Buffer.from(key.getPublicSSH(), "base64")
          )
        ) {
          log.info("Key data mismatch");
          continue;
        }

        // Then verify signature if present
        if (
          context.signature &&
          key.verify(context.blob, context.signature) !== true
        ) {
          continue;
        }

        log.info("Authentication successful");
        client.on("session", (accept, reject) => {
          this.sessionHandler(client, accept, reject, context.username, false);
        });
        return context.accept();
      }

      return context.reject();
    } catch (e) {
      log.error("Auth error:", e);
      return context.reject();
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
      this.authenticationHandler(client, context as ssh2.PublicKeyAuthContext)
    );

    client.on("error", (err) => {
      log.error("Client connection error:", err);
    });
  }
}
