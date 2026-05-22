declare module 'pacote' {
  interface Manifest {
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
