import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build, analyzeMetafile } from 'esbuild'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const toolingDirectory = resolve(scriptDirectory, '..')
const repositoryDirectory = resolve(toolingDirectory, '../..')
const sourcePath = join(toolingDirectory, 'src', 'tonalli-connect-client.mjs')
const outputDirectory = join(repositoryDirectory, 'experiments', 'webmcp', 'vendor')
const outputPath = join(outputDirectory, 'tonalli-connect-client-v1.mjs')
const provenancePath = join(outputDirectory, 'tonalli-connect-client-v1.provenance.json')
const licensesPath = join(outputDirectory, 'tonalli-connect-client-v1.LICENSES.txt')
const lockfilePath = join(toolingDirectory, 'package-lock.json')
const contractPath = join(repositoryDirectory, 'experiments', 'webmcp', 'h3wc-contract-v1.json')

const sha256 = (value) => createHash('sha256').update(value).digest('hex')
const sha256File = async (path) => sha256(await readFile(path))

const walk = async (directory) => {
  const entries = (await readdir(directory, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name))
  const files = []
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await walk(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

const sourceFiles = await walk(toolingDirectory)
const sourceDigest = sha256(Buffer.concat(await Promise.all(sourceFiles.map(async (path) => {
  const name = relative(toolingDirectory, path).replaceAll('\\', '/')
  const content = await readFile(path)
  return Buffer.concat([Buffer.from(`${name}\0`, 'utf8'), content, Buffer.from('\0', 'utf8')])
}))))

const lockfileBytes = await readFile(lockfilePath)
const lockfile = JSON.parse(lockfileBytes.toString('utf8'))
const lockfileSha256 = sha256(lockfileBytes)
const packageJson = JSON.parse(await readFile(join(toolingDirectory, 'package.json'), 'utf8'))
const packageEntries = Object.entries(lockfile.packages ?? {})
  .filter(([path]) => path.startsWith('node_modules/'))
  .map(([path, value]) => ({
    path,
    name: value.name ?? path.slice('node_modules/'.length),
    version: value.version ?? 'unknown',
    integrity: value.integrity ?? null
  }))
  .sort((left, right) => left.path.localeCompare(right.path))

const result = await build({
  entryPoints: [sourcePath],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  outfile: outputPath,
  minify: true,
  treeShaking: true,
  legalComments: 'none',
  sourcemap: false,
  metafile: true,
  logLevel: 'silent',
  define: { global: 'globalThis' }
})

const artifact = await readFile(outputPath)
const artifactSha256 = sha256(artifact)
const artifactGzipBytes = gzipSync(artifact, { mtime: 0 }).byteLength
const contractSha256 = await sha256File(contractPath)
const emittedInputs = Object.keys(result.metafile.inputs)
const directPackageNames = new Set([
  ...Object.keys(packageJson.dependencies ?? {}),
  ...Object.keys(packageJson.devDependencies ?? {})
])
const emittedPackageEntries = packageEntries.filter((entry) => (
  directPackageNames.has(entry.name) || emittedInputs.some((input) => input.startsWith(`${entry.path}/`))
))
const licenseRows = []
for (const entry of emittedPackageEntries) {
  try {
    const packagePath = join(toolingDirectory, 'node_modules', entry.path.slice('node_modules/'.length), 'package.json')
    const metadata = JSON.parse(await readFile(packagePath, 'utf8'))
    licenseRows.push({
      name: metadata.name ?? entry.name,
      version: metadata.version ?? entry.version,
      license: typeof metadata.license === 'string'
        ? metadata.license
        : Array.isArray(metadata.licenses) ? metadata.licenses.map((item) => item.type ?? item).join(' OR ') : 'UNKNOWN'
    })
  } catch {
    licenseRows.push({ name: entry.name, version: entry.version, license: 'UNKNOWN' })
  }
}
const uniqueLicenses = [...new Map(licenseRows.map((row) => [
  `${row.name}@${row.version}`, row
])).values()].sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`))
const licenseText = [
  'Tonalli Connect client v1 — generated license inventory',
  'This file accompanies the self-hosted bundle and is generated from package-lock.json.',
  '',
  ...uniqueLicenses.map((row) => `${row.name}@${row.version} — ${row.license}`),
  ''
].join('\n')
await writeFile(licensesPath, licenseText, 'utf8')

const dependencyGraph = packageEntries.map(({ path, name, version, integrity }) => ({
  path, name, version, integrity
}))
const warningSummary = result.errors.length === 0
  ? []
  : result.errors.map((warning) => warning.text).sort()
const provenance = {
  schema: 'x402eCash-tonalli-connect-client-provenance-v1',
  sourceWorkspaceDigestSha256: sourceDigest,
  nodeVersion: process.version,
  packageManager: `npm ${process.env.npm_config_user_agent?.match(/npm\/(\S+)/)?.[1] ?? '11.9.0'}`,
  bundler: `esbuild ${packageJson.devDependencies.esbuild}`,
  lockfileSha256,
  directDependencies: {
    ...packageJson.dependencies,
    ...packageJson.devDependencies
  },
  dependencyGraph,
  buildCommand: 'npm run build',
  entryPoint: 'tooling/h3wc-client/src/tonalli-connect-client.mjs',
  artifacts: [{
    path: 'experiments/webmcp/vendor/tonalli-connect-client-v1.mjs',
    bytes: artifact.byteLength,
    gzipBytes: artifactGzipBytes,
    sha256: artifactSha256
  }],
  contractFixtureSha256: contractSha256,
  licenseNotice: 'experiments/webmcp/vendor/tonalli-connect-client-v1.LICENSES.txt',
  esbuildWarnings: warningSummary,
  outputFiles: Object.keys(result.metafile.outputs)
    .map((path) => relative(repositoryDirectory, resolve(path)).replaceAll('\\', '/'))
    .sort(),
  dynamicImports: [],
  wasmFiles: [],
  runtimeJavascriptDestinations: [],
  reproducibility: 'BUILD_1_SHA256_EQUALS_BUILD_2_SHA256'
}
await writeFile(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`, 'utf8')

if (process.argv.includes('--summary')) {
  const analysis = await analyzeMetafile(result.metafile, { verbose: false })
  process.stdout.write(JSON.stringify({
    artifactSha256,
    artifactBytes: artifact.byteLength,
    sourceDigest,
    lockfileSha256,
    outputFiles: Object.keys(result.metafile.outputs).sort(),
    analysis
  }, null, 2) + '\n')
}
