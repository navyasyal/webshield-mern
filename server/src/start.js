import { spawn } from "node:child_process";

const processes = [
  spawn("node", ["src/index.js"], { stdio: "inherit" }),
  spawn("node", ["src/worker.js"], { stdio: "inherit" }),
];

let stopping = false;

function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;

  for (const child of processes) {
    if (!child.killed) child.kill("SIGTERM");
  }

  setTimeout(() => process.exit(code), 3000).unref();
}

for (const child of processes) {
  child.on("error", (error) => {
    console.error("Process startup error:", error);
    shutdown(1);
  });

  child.on("exit", (code) => {
    if (!stopping) {
      console.error("API or worker exited:", code);
      shutdown(code || 1);
    }
  });
}

process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
