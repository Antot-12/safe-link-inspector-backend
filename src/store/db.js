import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'

const DATA_DIR = process.env.VERCEL ? '/tmp' : join(process.cwd(), 'data')
await mkdir(DATA_DIR, { recursive: true })
const DB_FILE = join(DATA_DIR, 'db.json')

const adapter = new JSONFile(DB_FILE)
const db = new Low(adapter, { items: [] })
await db.read()
if (!Array.isArray(db.data.items)) db.data.items = []

export async function addRecord(rec) {
  const idx = db.data.items.findIndex(x => x.id === rec.id)
  if (idx >= 0) db.data.items[idx] = rec
  else db.data.items.push(rec)
  await db.write()
  return rec
}

export function getAll() {
  return [...db.data.items].sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
}

export function getById(id) {
  return db.data.items.find(x => x.id === id) || null
}

export async function removeById(id) {
  const before = db.data.items.length
  db.data.items = db.data.items.filter(x => x.id !== id)
  const changed = db.data.items.length !== before
  if (changed) await db.write()
  return changed
}

export async function clearAll() {
  db.data.items = []
  await db.write()
}
