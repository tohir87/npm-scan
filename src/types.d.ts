declare module 'pacote' {
  export interface Manifest {
    name: string;
    version: string;
    [key: string]: unknown;
  }

  interface ExtractOptions {
    ignoreScripts?: boolean;
    [key: string]: unknown;
  }

  interface Pacote {
    manifest(spec: string, opts?: Record<string, unknown>): Promise<Manifest>;
    extract(spec: string, dest: string, opts?: ExtractOptions): Promise<void>;
  }

  const pacote: Pacote;
  export default pacote;
}

declare module 'hosted-git-info' {
  interface HostedGit {
    type: string;
    domain: string;
    user: string | null;
    project: string | null;
  }

  interface HostedGitInfo {
    /** Returns null for anything that isn't a recognised git host shorthand or URL. */
    fromUrl(url: string, opts?: Record<string, unknown>): HostedGit | undefined;
  }

  const hostedGitInfo: HostedGitInfo;
  export default hostedGitInfo;
}
