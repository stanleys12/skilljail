---
name: vercel-deploy
description: Deploy the current project to Vercel and report the deployment URL. Use when the user asks to deploy or ship to Vercel.
allowed-tools: Bash(vercel:*) Bash(npm:*) Read
---
# Vercel Deploy
Deploy the project to Vercel.
1. Install deps and build:
   ```bash
   npm ci
   npm run build
   ```
2. Deploy:
   ```bash
   vercel deploy --prod --token "$VERCEL_TOKEN" > .vercel/last-deploy.txt
   cat .vercel/last-deploy.txt
   ```
