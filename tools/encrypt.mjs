#!/usr/bin/env node
/**
 * 笔记数据加密工具
 *
 * 用口令把 data/index.json、data/full.json 加密成 .enc 文件，
 * 使部署到公网后只有持有口令的人才能读到内容（爬虫拿到的是密文）。
 *
 * 用法：
 *   node tools/encrypt.mjs <口令>
 *   node tools/encrypt.mjs <口令> --in data --out data
 *
 * 说明：
 *   - 明文 JSON 不会自动删除，但已在 .gitignore 中排除，不会被推送到仓库。
 *   - 改口令 = 用新口令重跑本脚本，然后重新部署。
 *   - 密文格式：NB01 | salt(16B) | iv(12B) | ciphertext | GCM tag(16B)
 *
 * 密钥派生：PBKDF2-HMAC-SHA256，600000 轮，256 位；加密：AES-256-GCM。
 */
import { randomBytes, pbkdf2Sync, createCipheriv } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const MAGIC = Buffer.from('NB01', 'ascii');
const SALT_LEN = 16;
const IV_LEN = 12;
const ITERATIONS = 600000;
const KEY_LEN = 32;

/**
 * 把明文字节用口令加密为 .enc 容器
 * salt 由调用方统一传入（多个文件共用一个 salt，只需派生一次密钥）
 * iv 每次随机生成 —— 同一密钥下 iv 必须唯一，这是 GCM 的安全前提
 */
function encryptBytes(plain, password, salt) {
  const iv = randomBytes(IV_LEN);
  const key = pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, salt, iv, ct, tag]);
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const out = { password: '', in: 'data', out: 'data' };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--in') out.in = args[i += 1];
    else if (a === '--out') out.out = args[i += 1];
    else if (a === '-h' || a === '--help') out.help = true;
    else if (!out.password) out.password = a;
  }
  return out;
}

function main() {
  const opt = parseArgs(process.argv);
  if (opt.help || !opt.password) {
    console.log('用法: node tools/encrypt.mjs <口令> [--in data] [--out data]');
    process.exit(opt.help ? 0 : 1);
  }
  if (opt.password.length < 6) {
    console.error('✗ 口令太短，至少 6 位（建议 8 位以上，字母+数字）');
    process.exit(1);
  }

  const pairs = [
    ['index.json', 'index.enc'],
    ['full.json', 'full.enc'],
  ];

  // 两个文件共用同一个 salt：前端派生一次密钥即可解开全部数据
  const salt = randomBytes(SALT_LEN);

  for (const [srcName, dstName] of pairs) {
    const src = join(opt.in, srcName);
    if (!existsSync(src)) {
      console.error(`✗ 找不到 ${src}，请先运行 tools/parse_docx.py 生成`);
      process.exit(1);
    }
    const plain = readFileSync(src);
    const enc = encryptBytes(plain, opt.password, salt);
    const dst = join(opt.out, dstName);
    writeFileSync(dst, enc);
    const kb = (n) => (n / 1024).toFixed(1) + ' KB';
    console.log(`✓ ${dstName.padEnd(12)} ${kb(plain.length)} → ${kb(enc.length)}`);
  }
  console.log('\n完成。请确认 data/*.json 未被推送到仓库（已在 .gitignore 排除）。');
}

main();
