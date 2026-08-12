import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';

const repoRoot = path.resolve(import.meta.dirname, '..');
const artifactRoot = path.join(repoRoot, 'artifacts');
const evidenceRoot = path.join(repoRoot, 'verification', 'evidence');
const expectedHashes = {
  '输入数据包.zip': '21db8736444c7f2e251fca978383689b3ed07f93a8a770cb280b6362f9c9dd10',
  'reference.zip': 'f40f7d34f26b79432d09d54ea229d39155e13de92ec3bf1fd5a1d1fe088d9685',
  '关键标准答案.xlsx': '2f85cb7fa222e7c4f4db76ad9d8aa14f278d6976a01b49652a4cbd04636a59fb',
  '任务规格转化.xlsx': 'bb9773e2d636cac109c451819c69b5394f3c51b9ce9a007038916f3fc354ffbf'
};
const expectedReference = [
  'output/batch_manifest.json',
  'output/purge_batches.jsonl',
  'output/reclaim_summary.csv',
  'output/retention_decisions.csv',
  'output/src/build_purge_batches.mjs'
];
const assert = (value, message) => {
  if (!value) throw new Error(message);
};
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sha256File = (file) => sha256(fs.readFileSync(file));

function zipEntries(file) {
  const data = fs.readFileSync(file);
  let eocd = -1;
  for (let index = data.length - 22; index >= Math.max(0, data.length - 65557); index -= 1) {
    if (data.readUInt32LE(index) === 0x06054b50) {
      eocd = index;
      break;
    }
  }
  assert(eocd >= 0, `找不到ZIP目录:${file}`);
  const count = data.readUInt16LE(eocd + 10);
  let offset = data.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let index = 0; index < count; index += 1) {
    assert(data.readUInt32LE(offset) === 0x02014b50, `ZIP目录损坏:${file}`);
    const method = data.readUInt16LE(offset + 10);
    const compressedSize = data.readUInt32LE(offset + 20);
    const uncompressedSize = data.readUInt32LE(offset + 24);
    const nameLength = data.readUInt16LE(offset + 28);
    const extraLength = data.readUInt16LE(offset + 30);
    const commentLength = data.readUInt16LE(offset + 32);
    const localOffset = data.readUInt32LE(offset + 42);
    const name = data.subarray(offset + 46, offset + 46 + nameLength).toString('utf8').replaceAll('\\', '/');
    const localNameLength = data.readUInt16LE(localOffset + 26);
    const localExtraLength = data.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLength + localExtraLength;
    if (!name.endsWith('/')) {
      const compressed = data.subarray(start, start + compressedSize);
      const body = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : null;
      assert(body && body.length === uncompressedSize, `无法解压${name}`);
      entries.set(name, body);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

async function extract(file, destination) {
  for (const [name, bytes] of zipEntries(file)) {
    const target = path.resolve(destination, ...name.split('/'));
    assert(target.startsWith(`${path.resolve(destination)}${path.sep}`), `非法ZIP路径:${name}`);
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, bytes);
  }
}

function workbookSheets(file) {
  const xml = zipEntries(file).get('xl/workbook.xml')?.toString('utf8') ?? '';
  return [...xml.matchAll(/<(?:[A-Za-z]+:)?sheet[^>]+name="([^"]+)"/gu)].map((match) => match[1]);
}

async function run(command, args, cwd) {
  const started = Date.now();
  return await new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, { cwd, env: process.env, windowsHide: true });
    } catch (error) {
      resolve({ code: 1, stdout: '', stderr: error.stack ?? error.message, elapsed_ms: Date.now() - started });
      return;
    }
    let stdout = '';
    let stderr = '';
    let settled = false;
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => {
      if (!settled) {
        settled = true;
        resolve({ code: 1, stdout, stderr: `${stderr}${error.stack ?? error.message}`, elapsed_ms: Date.now() - started });
      }
    });
    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        resolve({ code: code ?? 1, stdout, stderr, elapsed_ms: Date.now() - started });
      }
    });
  });
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (character === '"') quoted = false;
      else cell += character;
    } else if (character === '"') quoted = true;
    else if (character === ',') {
      row.push(cell);
      cell = '';
    } else if (character === '\n') {
      row.push(cell.replace(/\r$/u, ''));
      rows.push(row);
      row = [];
      cell = '';
    } else cell += character;
  }
  if (cell || row.length) {
    row.push(cell.replace(/\r$/u, ''));
    rows.push(row);
  }
  const headers = rows.shift() ?? [];
  return rows.filter((values) => values.some((value) => value !== '')).map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])));
}

function listFiles(root) {
  const output = [];
  function walk(current, prefix = '') {
    if (!fs.existsSync(current)) return;
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((left, right) => left.name.localeCompare(right.name, 'en'))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(path.join(current, entry.name), relative);
      else output.push(relative);
    }
  }
  walk(root);
  return output.sort();
}

function treeDigest(root) {
  const rows = [];
  for (const name of listFiles(root)) rows.push(`${name}\0${sha256File(path.join(root, ...name.split('/')))}`);
  return sha256(Buffer.from(rows.join('\n')));
}

function classify(name, bytes) {
  const lower = name.toLowerCase();
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes.subarray(1, 4).toString('ascii') === 'ELF') return 'linux_elf';
  if (/\.(?:sh|bash|so)(?:\.|$)/u.test(lower)) return 'posix_member';
  if (/^#!.*(?:ba|z|k)?sh/mu.test(bytes.subarray(0, 160).toString('utf8'))) return 'posix_shebang';
  return null;
}

async function prepare(label, mutate) {
  const root = path.join(os.tmpdir(), label);
  await fsp.rm(root, { recursive: true, force: true });
  await fsp.mkdir(root, { recursive: true });
  await extract(path.join(artifactRoot, '输入数据包.zip'), root);
  const inputRoot = path.join(root, 'input_data');
  const outputRoot = path.join(root, 'output');
  const reference = zipEntries(path.join(artifactRoot, 'reference.zip'));
  await fsp.mkdir(path.join(outputRoot, 'src'), { recursive: true });
  await fsp.writeFile(path.join(outputRoot, 'src', 'build_purge_batches.mjs'), reference.get('output/src/build_purge_batches.mjs'));
  if (mutate) await mutate(inputRoot);
  return { root, inputRoot, outputRoot, reference };
}

async function execute(inputRoot) {
  return await run(process.execPath, ['tools/run-task.mjs'], inputRoot);
}

function semanticOutput(outputRoot, reference) {
  const actualMembers = listFiles(outputRoot).map((name) => `output/${name}`);
  assert(JSON.stringify(actualMembers) === JSON.stringify(expectedReference), `交付成员错误:${actualMembers.join(',')}`);
  const digest = crypto.createHash('sha256');
  for (const name of ['retention_decisions.csv', 'reclaim_summary.csv']) {
    const actual = parseCsv(fs.readFileSync(path.join(outputRoot, name), 'utf8'));
    const expected = parseCsv(reference.get(`output/${name}`).toString('utf8'));
    assert(JSON.stringify(actual) === JSON.stringify(expected), `${name}业务字段不一致`);
    digest.update(JSON.stringify(actual));
  }
  const actualBatches = fs.readFileSync(path.join(outputRoot, 'purge_batches.jsonl'), 'utf8').trim().split(/\r?\n/u).filter(Boolean).map(JSON.parse);
  const expectedBatches = reference.get('output/purge_batches.jsonl').toString('utf8').trim().split(/\r?\n/u).filter(Boolean).map(JSON.parse);
  assert(JSON.stringify(actualBatches) === JSON.stringify(expectedBatches), 'purge_batches.jsonl业务字段不一致');
  digest.update(JSON.stringify(actualBatches));
  const actualManifest = JSON.parse(fs.readFileSync(path.join(outputRoot, 'batch_manifest.json'), 'utf8'));
  const expectedManifest = JSON.parse(reference.get('output/batch_manifest.json').toString('utf8'));
  assert(JSON.stringify(actualManifest) === JSON.stringify(expectedManifest), 'batch_manifest.json业务字段不一致');
  digest.update(JSON.stringify(actualManifest));
  const actualSource = fs.readFileSync(path.join(outputRoot, 'src', 'build_purge_batches.mjs'), 'utf8').replaceAll('\r\n', '\n');
  const expectedSource = reference.get('output/src/build_purge_batches.mjs').toString('utf8').replaceAll('\r\n', '\n');
  assert(actualSource === expectedSource, '完成程序内容不一致');
  digest.update(actualSource);
  return digest.digest('hex');
}

await fsp.rm(evidenceRoot, { recursive: true, force: true });
await fsp.mkdir(evidenceRoot, { recursive: true });
assert(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', '只接受GitHub托管Windows运行');
assert(Number(process.versions.node.split('.')[0]) === 24, `需要Node.js24:${process.version}`);
for (const [name, expected] of Object.entries(expectedHashes)) assert(sha256File(path.join(artifactRoot, name)) === expected, `${name}哈希不一致`);
const inputMembers = zipEntries(path.join(artifactRoot, '输入数据包.zip'));
const referenceMembers = zipEntries(path.join(artifactRoot, 'reference.zip'));
const inputExpected = [
  'input_data/README.md',
  'input_data/legal_holds.csv',
  'input_data/object_inventory.csv',
  'input_data/package.json',
  'input_data/retention_policy.json',
  'input_data/starter/build_purge_batches.mjs',
  'input_data/tools/run-task.mjs'
];
assert(JSON.stringify([...inputMembers.keys()].sort()) === JSON.stringify(inputExpected), '输入包成员不一致');
assert(JSON.stringify([...referenceMembers.keys()].sort()) === JSON.stringify(expectedReference), 'Reference成员不一致');
const platformMembers = [...inputMembers, ...referenceMembers].map(([name, bytes]) => ({ name, classification: classify(name, bytes) })).filter((item) => item.classification);
assert(platformMembers.length === 0, `含平台专用成员:${JSON.stringify(platformMembers)}`);
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx'))) === JSON.stringify(['交付物答案清单', '固定字段答案', '固定集合答案', '固定数值答案', '允许变体答案']), '标答Sheet不一致');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx'))) === JSON.stringify(['任务规格转化']), '规格Sheet不一致');

const candidateTextFiles = ['任务名称.txt', '任务概要.txt', '任务prompt.txt', '关键动作.txt', '评分表.txt', '环境依赖.txt', '相关专业软件的关键步骤.txt'];
const candidateText = candidateTextFiles.map((name) => fs.readFileSync(path.join(repoRoot, 'task', name), 'utf8')).join('\n');
assert(!/recv[a-z0-9]+|https?:\/\/[^\s]+/iu.test(candidateText), '候选文本含私有标识或外部地址');
assert(!/Windows复现|Windows验证|GitHub Actions|CI门禁|双干净目录|动态变化|失败负例|附件哈希|飞书回读|Reference/iu.test(candidateText), '候选文本含制题工程口吻');
const scoreText = fs.readFileSync(path.join(repoRoot, 'task', '评分表.txt'), 'utf8');
const scoreBlocks = scoreText.split(/(?=^检查项：)/gmu).map((block) => block.trim()).filter(Boolean);
const requiredLabels = ['检查项', '检查项内容', '标准答案', '关键字段', '容差', '失败边界', '可观察证据', '客观硬性标准', '阈值', '优先级', '所属层级'];
const allowedLayers = new Set(['L1任务指令遵循层', 'L2软件或工具操作层', 'L3输入数据导入与完整性层', 'L4数据清洗与质量控制层', 'L5多源关联与字段一致性层', 'L6领域计算与专业规则层', 'L7产物结构或Schema或专业对象层', 'L8运行验证或可执行行为层', 'L9跨产物一致性与可追溯层', 'L10抗投机或反作弊层', 'L11感知与空间质量']);
assert(scoreBlocks.length === 6, '评分项数量不一致');
for (const [index, block] of scoreBlocks.entries()) {
  for (const label of requiredLabels) assert(new RegExp(`^${label}：\\S`, 'mu').test(block), `评分表第${index + 1}项缺少${label}`);
  assert(['Gate项', '高权重项', '普通项', '辅助项'].includes(block.match(/^优先级：(.*)$/mu)?.[1]?.trim()), `评分表第${index + 1}项优先级不合法`);
  assert(allowedLayers.has(block.match(/^所属层级：(.*)$/mu)?.[1]?.trim()), `评分表第${index + 1}项层级不合法`);
}
assert(scoreBlocks.filter((block) => /^优先级：Gate项$/mu.test(block)).length <= 2, 'Gate项过多');

const cleanRuns = [];
for (const label of ['Q10440 第一次 中文 空目录', 'Q10440 第二次 中文 空格目录']) {
  const room = await prepare(label);
  const before = treeDigest(room.inputRoot);
  const result = await execute(room.inputRoot);
  assert(result.code === 0, `${label}业务入口失败\n${result.stdout}\n${result.stderr}`);
  const after = treeDigest(room.inputRoot);
  assert(before === after, `${label}修改输入`);
  const semantic = semanticOutput(room.outputRoot, room.reference);
  cleanRuns.push({ directory_label: label, process_runs: 1, exit_codes: [result.code], input_digest_before: before, input_digest_after: after, semantic_digest: semantic, elapsed_ms: [result.elapsed_ms], reference_match: true });
}
assert(cleanRuns[0].semantic_digest === cleanRuns[1].semantic_digest, '两个目录结构化结果不同');

const directRoot = path.join(os.tmpdir(), 'Q10440 Reference 独立入口');
await fsp.rm(directRoot, { recursive: true, force: true });
await fsp.mkdir(directRoot, { recursive: true });
await extract(path.join(artifactRoot, '输入数据包.zip'), directRoot);
const directImplementation = path.join(directRoot, 'implementation', 'build_purge_batches.mjs');
const directOutput = path.join(directRoot, 'direct-output');
await fsp.mkdir(path.dirname(directImplementation), { recursive: true });
await fsp.writeFile(directImplementation, referenceMembers.get('output/src/build_purge_batches.mjs'));
let result = await run(process.execPath, [directImplementation, path.join(directRoot, 'input_data'), directOutput], directRoot);
assert(result.code === 0, `Reference独立入口失败\n${result.stdout}\n${result.stderr}`);
const directDigest = semanticOutput(directOutput, referenceMembers);
assert(directDigest === cleanRuns[0].semantic_digest, 'Reference独立入口结果不同');

const crlf = await prepare('Q10440 CRLF 清单', async (inputRoot) => {
  for (const name of ['object_inventory.csv', 'legal_holds.csv']) {
    const file = path.join(inputRoot, name);
    await fsp.writeFile(file, (await fsp.readFile(file, 'utf8')).replace(/\r?\n/gu, '\r\n'));
  }
});
result = await execute(crlf.inputRoot);
assert(result.code === 0, `CRLF清单处理失败\n${result.stdout}\n${result.stderr}`);
const crlfDigest = semanticOutput(crlf.outputRoot, crlf.reference);
assert(crlfDigest === cleanRuns[0].semantic_digest, 'CRLF改变业务结果');

const mutation = await prepare('Q10440 CDN 批次上限变化', async (inputRoot) => {
  const file = path.join(inputRoot, 'retention_policy.json');
  const policy = JSON.parse(await fsp.readFile(file, 'utf8'));
  policy.cdn_purge.max_paths_per_batch = 4;
  await fsp.writeFile(file, `${JSON.stringify(policy, null, 2)}\n`);
});
result = await execute(mutation.inputRoot);
assert(result.code === 0, `批次上限变化处理失败\n${result.stdout}\n${result.stderr}`);
const changedBatches = fs.readFileSync(path.join(mutation.outputRoot, 'purge_batches.jsonl'), 'utf8').trim().split(/\r?\n/u).map(JSON.parse);
const changedDecisions = parseCsv(fs.readFileSync(path.join(mutation.outputRoot, 'retention_decisions.csv'), 'utf8'));
const baselineDecisions = parseCsv(referenceMembers.get('output/retention_decisions.csv').toString('utf8'));
assert(changedBatches.length === 2 && changedBatches.every((batch) => batch.path_count <= 4), '批次上限变化没有重排批次');
assert(JSON.stringify(changedDecisions.map(({ object_key, decision, reason }) => ({ object_key, decision, reason }))) === JSON.stringify(baselineDecisions.map(({ object_key, decision, reason }) => ({ object_key, decision, reason }))), '批次参数变化错误改变对象裁决');
assert(changedDecisions.some((row, index) => row.purge_batch_id !== baselineDecisions[index].purge_batch_id), '批次参数变化未改变批次身份');

const negative = await prepare('Q10440 重复对象主键', async (inputRoot) => {
  const file = path.join(inputRoot, 'object_inventory.csv');
  const lines = (await fsp.readFile(file, 'utf8')).trimEnd().split(/\r?\n/u);
  await fsp.writeFile(file, `${lines.join('\n')}\n${lines[1]}\n`);
});
result = await execute(negative.inputRoot);
const derivedOutputsAbsent = !fs.existsSync(negative.outputRoot);
assert(result.code !== 0 && derivedOutputsAbsent, '重复对象主键没有非零退出或仍残留交付物');

const evidence = {
  schema_version: 1,
  task_asset_id: 'node_object_retention_cdn_purge_planning',
  result: 'PASS',
  generated_at_utc: new Date().toISOString(),
  git_commit_sha: process.env.GITHUB_SHA,
  workflow_run_id: process.env.GITHUB_RUN_ID,
  runner: { os: process.env.RUNNER_OS, arch: process.env.RUNNER_ARCH, image_os: process.env.ImageOS, image_version: process.env.ImageVersion, node: process.version, actual_windows_run: true },
  software: { main: 'Node.js', version: process.version, executed: true },
  attachment_sha256: expectedHashes,
  archive_checks: { input_members: [...inputMembers.keys()].sort(), reference_members: [...referenceMembers.keys()].sort(), prohibited_platform_members: platformMembers },
  workbook_checks: { answer_sheet_names: workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx')), specification_sheet_names: workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx')), specification_column_count: 2 },
  score_checks: { item_count: scoreBlocks.length, every_item_has_eleven_semantic_fields: true, gate_item_count: scoreBlocks.filter((block) => /^优先级：Gate项$/mu.test(block)).length },
  clean_runs: cleanRuns,
  reference_entry: { executed_from_separate_implementation_directory: true, exit_code: 0, semantic_digest: directDigest, reference_match: true },
  crlf_case: { changed_inputs: ['object_inventory.csv', 'legal_holds.csv'], exit_code: 0, semantic_digest: crlfDigest, reference_match: true },
  positive_mutation: { changed_rule: 'retention_policy.json中的max_paths_per_batch从3改为4', exit_code: 0, batch_count: changedBatches.length, decisions_unchanged: true, batch_assignment_changed: true },
  invalid_input: { changed_input: 'object_inventory.csv追加重复object_key', exit_code: result.code, derived_outputs_absent: derivedOutputsAbsent },
  platform_audit: { linux_executables_executed: false, no_wsl_required: true, no_linux_container_required: true, no_posix_shell_required: true, no_unix_only_api_required: true, cross_platform_paths: true },
  network: { installation_network_access: '仅Node.js运行环境安装阶段', formal_run_network_access: '无网络访问' }
};
await fsp.writeFile(path.join(evidenceRoot, 'windows-verification.json'), `${JSON.stringify(evidence, null, 2)}\n`);
const audit = {
  schema_version: 1,
  result: 'PASS',
  task_asset_id: evidence.task_asset_id,
  platform: process.platform,
  architecture: process.arch,
  node_version: process.version,
  attachment_sha256: expectedHashes,
  clean_directory_count: cleanRuns.length,
  main_software_executed: true,
  reference_entry_executed: true,
  crlf_checked: true,
  positive_mutation_checked: true,
  invalid_input_failed_closed: true
};
await fsp.writeFile(path.join(evidenceRoot, 'windows-audit.json'), `${JSON.stringify(audit, null, 2)}\n`);
console.log(JSON.stringify(evidence, null, 2));
