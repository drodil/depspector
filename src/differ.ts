import fs from "fs";
import path from "path";
import axios from "axios";
import * as tar from "tar";
import semver from "semver";
import os from "os";
import { promisify } from "util";
import stream from "stream";
import { DepspectorConfig } from "./config";
import { fetchPackageMetadata } from "./registryUtil";

const pipeline = promisify(stream.pipeline);

export interface DiffResult {
  file: string;
  changeType: "added" | "modified" | "deleted";
  changedLines: { start: number; end: number }[];
}

export class Differ {
  private cacheDir: string;
  private registryUrl: string;
  private axiosConfig: any;
  private config: DepspectorConfig;

  constructor(config?: DepspectorConfig) {
    this.config = config || {};
    const defaultCacheDir = path.join(os.tmpdir(), "depspector-cache");
    this.cacheDir = config?.cacheDir
      ? path.resolve(config.cacheDir)
      : defaultCacheDir;

    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }

    this.registryUrl = config?.npm?.registry ?? "https://registry.npmjs.org";

    this.axiosConfig = {};
    if (config?.npm?.token) {
      this.axiosConfig.headers = {
        Authorization: `Bearer ${config.npm.token}`,
      };
    } else if (config?.npm?.username && config?.npm?.password) {
      const credentials = Buffer.from(
        `${config.npm.username}:${config.npm.password}`,
      ).toString("base64");
      this.axiosConfig.headers = {
        Authorization: `Basic ${credentials}`,
      };
    }
  }

  async getPreviousVersion(
    packageName: string,
    currentVersion: string,
  ): Promise<string | null> {
    try {
      const metadata = await fetchPackageMetadata(packageName, this.config);
      if (!metadata) return null;

      const versions = Object.keys(metadata.versions);
      const sortedVersions = versions.sort((a, b) => semver.compare(a, b));
      const currentIndex = sortedVersions.indexOf(currentVersion);

      if (currentIndex > 0) {
        return sortedVersions[currentIndex - 1];
      }
      return null;
    } catch (error) {
      console.error(`Failed to fetch version info for ${packageName}:`, error);
      return null;
    }
  }

  async downloadAndExtract(
    packageName: string,
    version: string,
  ): Promise<string> {
    const tarballUrl = `${this.registryUrl}/${packageName}/-/${packageName.split("/").pop()}-${version}.tgz`;
    const extractPath = path.join(
      this.cacheDir,
      `${packageName.replace("/", "-")}-${version}`,
    );

    if (fs.existsSync(extractPath)) {
      const files = fs.readdirSync(extractPath);
      if (files.length > 0) {
        return extractPath;
      }
      fs.rmdirSync(extractPath);
    }

    try {
      const response = await axios({
        method: "get",
        url: tarballUrl,
        responseType: "stream",
        ...this.axiosConfig,
      });

      fs.mkdirSync(extractPath, { recursive: true });

      await pipeline(
        response.data,
        tar.x({
          cwd: extractPath,
          strip: 1,
        }),
      );
    } catch (error) {
      if (fs.existsSync(extractPath)) {
        fs.rmSync(extractPath, { recursive: true, force: true });
      }
      throw error;
    }

    return extractPath;
  }

  compareFiles(
    oldPath: string,
    newPath: string,
  ): { start: number; end: number }[] {
    if (!fs.existsSync(oldPath)) {
      const content = fs.readFileSync(newPath, "utf-8");
      const lines = content.split("\n").length;
      return [{ start: 1, end: lines }];
    }

    const oldContent = fs.readFileSync(oldPath, "utf-8").split("\n");
    const newContent = fs.readFileSync(newPath, "utf-8").split("\n");

    const changes: { start: number; end: number }[] = [];

    const oldSet = new Set(oldContent.map((l) => l.trim()));

    let currentStart = -1;

    for (let i = 0; i < newContent.length; i++) {
      const line = newContent[i].trim();
      if (!oldSet.has(line) && line.length > 0) {
        if (currentStart === -1) {
          currentStart = i + 1;
        }
      } else {
        if (currentStart !== -1) {
          changes.push({ start: currentStart, end: i });
          currentStart = -1;
        }
      }
    }

    if (currentStart !== -1) {
      changes.push({ start: currentStart, end: newContent.length });
    }

    return changes;
  }

  async diffPackage(
    packageName: string,
    currentVersion: string,
    installPath: string,
  ): Promise<DiffResult[]> {
    const prevVersion = await this.getPreviousVersion(
      packageName,
      currentVersion,
    );
    if (!prevVersion) {
      return [];
    }

    const prevPath = await this.downloadAndExtract(packageName, prevVersion);
    const results: DiffResult[] = [];

    const walk = (dir: string) => {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        const relativePath = path.relative(installPath, fullPath);
        const prevFullPath = path.join(prevPath, relativePath);

        if (fs.statSync(fullPath).isDirectory()) {
          walk(fullPath);
        } else if (
          file.endsWith(".js") ||
          file.endsWith(".ts") ||
          file.endsWith(".mjs")
        ) {
          const changedLines = this.compareFiles(prevFullPath, fullPath);
          if (changedLines.length > 0) {
            results.push({
              file: fullPath,
              changeType: fs.existsSync(prevFullPath) ? "modified" : "added",
              changedLines,
            });
          }
        }
      }
    };

    walk(installPath);
    return results;
  }
}
