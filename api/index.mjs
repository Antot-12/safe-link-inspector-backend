import serverless from 'serverless-http'
import { createApp } from '../src/app.mjs'

const app = await createApp()
export default serverless(app)
