import fs from "fs";
import path from "path";
import crypto from "crypto";
import { AnalysisResult } from "./analyzer";

export interface CacheEntry {
  hash: string;
  timestamp: number;
  nodeModulesPath: string;
  version: string;
  results: AnalysisResult[];
}

export class PackageCache {
  private cacheFile: string;
  private cacheDir: string;
  private cache: Map<string, CacheEntry>; // key = `${name}@${version}`

  constructor(cacheDir: string) {
    this.cacheDir = cacheDir;
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    this.cacheFile = path.join(cacheDir, ".depspector-cache.json");
    this.cache = new Map();
    this.loadCache();
  }

  private loadCache(): void {
    try {
      if (fs.existsSync(this.cacheFile)) {
        const data = JSON.parse(fs.readFileSync(this.cacheFile, "utf-8"));
        this.cache = new Map(Object.entries(data));
      }
    } catch {
      this.cache = new Map();
    }
  }

  private saveCache(): void {
    try {
      const cacheDir = path.dirname(this.cacheFile);
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }
      const data = Object.fromEntries(this.cache);
      fs.writeFileSync(this.cacheFile, JSON.stringify(data, null, 2));
    } catch (error) {
      console.warn(`Failed to save cache: ${error}`);
    }
  }

  private hashDirectory(dirPath: string): string {
    try {
      if (!fs.existsSync(dirPath)) {
        return "";
      }

      const packageJsonPath = path.join(dirPath, "package.json");
      if (fs.existsSync(packageJsonPath)) {
        const content = fs.readFileSync(packageJsonPath, "utf-8");
        return crypto.createHash("sha256").update(content).digest("hex");
      }
    } catch {
      return "";
    }
    return "";
  }

  hasChanged(
    packageName: string,
    version: string,
    packagePath: string,
  ): boolean {
    const currentHash = this.hashDirectory(packagePath);
    if (!currentHash) return true;
    const key = `${packageName}@${version}`;
    const cached = this.cache.get(key);
    if (!cached) return true;
    return cached.hash !== currentHash;
  }

  getResults(packageName: string, version: string): AnalysisResult[] | null {
    const key = `${packageName}@${version}`;
    const cached = this.cache.get(key);
    return cached ? cached.results : null;
  }

  updateEntry(
    packageName: string,
    version: string,
    packagePath: string,
    results: AnalysisResult[],
  ): void {
    const hash = this.hashDirectory(packagePath);
    if (!hash) return;
    const key = `${packageName}@${version}`;
    this.cache.set(key, {
      hash,
      timestamp: Date.now(),
      nodeModulesPath: packagePath,
      version,
      results,
    });
    this.saveCache();
  }

  clearEntry(packageName: string, version: string): void {
    const key = `${packageName}@${version}`;
    this.cache.delete(key);
    this.saveCache();
  }

  clearAll(): void {
    this.cache.clear();

    if (fs.existsSync(this.cacheDir)) {
      fs.rmSync(this.cacheDir, { recursive: true, force: true });
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }
}
