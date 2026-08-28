import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const toolingDirectory = resolve(scriptDirectory, '..')
const repositoryDirectory = resolve(toolingDirectory, '../..')
const artifactPath = join(repositoryDirectory, 'experiments/webmcp/vendor/tonalli-connect-client-v1.mjs')
const provenancePath = join(repositoryDirectory, 'experiments/webmcp/vendor/tonalli-connect-client-v1.provenance.json')
const contractPath = join(repositoryDirectory, 'experiments/webmcp/h3wc-contract-v1.json')

const artifact = await readFile(artifactPath, 'utf8')
const provenance = JSON.parse(await readFile(provenancePath, 'utf8'))
const contract = JSON.parse(await readFile(contractPath, 'utf8'))

assert.equal(provenance.artifacts.length, 1)
assert.equal(provenance.artifacts[0].path, 'experiments/webmcp/vendor/tonalli-connect-client-v1.mjs')
assert.equal(provenance.artifacts[0].bytes, Buffer.byteLength(artifact))
assert.match(artifact, /H3WC_REQUIRED_NAMESPACES/)
assert.match(artifact, /ecash_getAccountIdentity/)
assert.match(artifact, /ecash_signMessage/)
assert.doesNotMatch(artifact, /https?:\/\/(?:cdn|unpkg|jsdelivr)/u)
assert.doesNotMatch(artifact, /import\s*\(/u)
assert.equal(provenance.dynamicImports.length, 0)
assert.equal(provenance.wasmFiles.length, 0)
assert.equal(contract.chain, 'ecash:1')
assert.deepEqual(contract.methods, ['ecash_getAccountIdentity', 'ecash_signMessage'])
assert.deepEqual(contract.events, [])
console.log('H3WC client tooling checks: 10/10 PASS')
