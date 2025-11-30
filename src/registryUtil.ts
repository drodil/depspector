import axios from "axios";
import { DepspectorConfig } from "./config";

const metadataCache = new Map<string, any>();

function buildAxiosConfig(config: DepspectorConfig) {
  const axiosConfig: any = { timeout: 5000 };
  if (config.npm?.token) {
    axiosConfig.headers = { Authorization: `Bearer ${config.npm.token}` };
  } else if (config.npm?.username && config.npm?.password) {
    const credentials = Buffer.from(
      `${config.npm.username}:${config.npm.password}`,
    ).toString("base64");
    axiosConfig.headers = { Authorization: `Basic ${credentials}` };
  }
  return axiosConfig;
}

export async function fetchPackageMetadata(
  name: string,
  config: DepspectorConfig,
): Promise<any | null> {
  if (metadataCache.has(name)) {
    return metadataCache.get(name);
  }
  const registry = (
    config.npm?.registry || "https://registry.npmjs.org"
  ).replace(/\/$/, "");
  const url = `${registry}/${name}`;
  try {
    const { data } = await axios.get(url, buildAxiosConfig(config));
    metadataCache.set(name, data);
    return data;
  } catch {
    return null;
  }
}

export function clearRegistryCache() {
  metadataCache.clear();
}
