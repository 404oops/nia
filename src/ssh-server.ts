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
    this.server = new SSH2Server(
      {
        hostKeys: [readFileSync(hostFilePath)],
      },
      this.connectionHandler.bind(this)
    ).listen(port, () => {
      log.info(`SSH Server listening on ${port}`);
    });
  }

  private async authenticationHandler(
    client: ssh2.Connection,
    context: ssh2.AuthContext
  ): Promise<void> {
    const reject = () => {
      context.reject();
    };

    const isLogs = context.username.startsWith("logs.");
    const username = isLogs ? context.username.substring(5) : context.username;

    try {
      log.info(`SSH Authentication Started for username: ${username}`);
      const config = this.containers.resolveConfig(username);
      if (config === undefined) {
        log.warn(`No config found for username: ${username}`);
        return reject();
      }

      const allowedKeys = config.ssh_keys
        .map((key) => ssh2.utils.parseKey(key) as ParsedKey | undefined)
        .filter((key) => key !== undefined) as ParsedKey[];
      if (allowedKeys.length <= 0) {
        log.warn(`No allowed keys found for username: ${username}`);
        return reject();
      }

      switch (context.method) {
        case "publickey": {
          let valid = false;
          for (const key of allowedKeys) {
            if (
              !context.key ||
              context.key.algo !== key.type ||
              !checkValue(context.key.data, Buffer.from(key.getPublicSSH())) ||
              (context.signature &&
                key.verify(context.blob, context.signature) !== true)
            ) {
              continue;
            }
            valid = true;
            break;
          }
          if (!valid) {
            log.warn(`Invalid key for username: ${username}`);
            return reject();
          }
          log.info(`Valid key for username: ${username}`);
          log.info(`SSH Authenticated for username: ${username}`);
          context.accept();
          return;
        }
        default:
          log.warn(`Unsupported authentication method: ${context.method}`);
          return context.reject(["publickey"]);
      }
    } catch (e) {
      log.error(`Error during authentication for username: ${username}`, e);
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
      log.info(`SSH Session Started for username: ${username}`);
      const container = await this.containers.resolveContainer(username);
      if (container === undefined) {
        log.warn(`No container found for username: ${username}`);
        return rejectSess();
      }

      if (isLogs) {
        log.debug("Log session");
        const containerStream = await container.logs({
          stderr: true,
          stdout: true,
        });
        const session = acceptSess();
        session.on("pty", (acceptPty, rejectPty) => {
          log.debug("PTY requested");
          acceptPty?.();
        });
        session.on("shell", async (acceptShell, rejectShell) => {
          log.debug("Shell requested");
          try {
            log.info("SSH Log session started");
            const stream = acceptShell();
            const sessionStream = new internal.PassThrough();
            sessionStream.on("data", (data) => stream.write(data));
            log.debug("Stream and containerStream setup");
            container.modem.demuxStream(
              containerStream,
              sessionStream,
              sessionStream
            );
            containerStream.on("end", () => {
              client.end();
            });
          } catch (e) {
            log.error("Shell rejected", e);
            rejectShell?.();
          }
        });
      } else {
        const exec = await container.exec({
          Cmd: ["/bin/bash"],
          AttachStderr: true,
          AttachStdout: true,
          AttachStdin: true,
          Tty: true,
        });
        const containerStream = await exec.start({ stdin: true });
        const session = acceptSess();
        session.on("pty", (acceptPty, rejectPty) => {
          log.debug("PTY requested");
          acceptPty?.();
        });
        session.on("shell", async (acceptShell, rejectShell) => {
          log.debug("Shell requested");
          try {
            log.info("SSH Shell started");
            const stream = acceptShell();
            container.modem.demuxStream(containerStream, stream, stream);
            containerStream.on("end", () => {
              client.end();
            });
            stream.pipe(containerStream);
          } catch (e) {
            log.error("Shell rejected", e);
            rejectShell?.();
          }
        });
      }
    } catch (e) {
      log.error(`Error during session handling for username: ${username}`, e);
      rejectSess();
    }
  }

  private connectionHandler(
    client: ssh2.Connection,
    info: ssh2.ClientInfo
  ): void {
    log.info(`Connection from ${info.ip} with ${info.header}`);
    client.on("authentication", (context) =>
      this.authenticationHandler(client, context)
    );
    client.on("ready", () => {
      log.info("Client authenticated and ready");
    });
    client.on("end", () => {
      log.info("Client disconnected");
    });
    client.on("error", (err) => {
      log.error("Client connection error", err);
    });
  }
}
