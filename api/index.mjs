import { createApp } from '../src/app.mjs'

const app = await createApp()

export default function handler(req, res) {
  // Vercel передає шлях типу /api/... — Express має такі ж префікси, нічого не зрізаємо
  return app(req, res)
}
