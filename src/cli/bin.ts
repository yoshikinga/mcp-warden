#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import process from "node:process";
import { runCli, type CliIoAdapter } from "./cli-runner.js";

const nodeCliIo: CliIoAdapter = {
  stdout(message: string): void {
    process.stdout.write(message);
  },
  stderr(message: string): void {
    process.stderr.write(message);
  },
  async readTextFile(filePath: string): Promise<string> {
    return readFile(filePath, "utf8");
  },
  env: process.env
};

async function main(): Promise<void> {
  try {
    const exitCode = await runCli(process.argv.slice(2), nodeCliIo);
    process.exitCode = exitCode;
  } catch (err: unknown) {
    const detail =
      err instanceof Error ? err.message : "Unexpected CLI runtime error.";
    process.stderr.write(`Fatal error: ${detail}\n`);
    process.exitCode = 2;
  }
}

void main();
