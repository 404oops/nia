/* eslint-disable @typescript-eslint/no-unused-vars */
import "module-alias/register";

import ContainerManager from "~/container-manager";
import HTTPServer from "./http-server";
import SSHServer from "./ssh-server";
import HTTPSServer from "./https-server";
import log from "./log";

const manager = new ContainerManager("./containers.yml");
new HTTPSServer("./ssl.yml", manager, 443);
new HTTPServer(manager, 80);
new SSHServer("./id_rsa", 22, manager);

process.on("uncaughtException", function (err) {
  log.error(err);
});
