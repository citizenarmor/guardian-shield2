# Guardian Shield Training — Website

Marketing site + class registration + certification platform for the
Guardian Rapid Response Shield 2-day training program.

## Run it on your computer
1. Install Node.js from https://nodejs.org
2. In this folder run:  npm install
3. Then run:            npm run dev
4. Open the address it prints (usually http://localhost:5173)

## Deploy
Push this folder to GitHub, then import the repository at https://vercel.com
(framework auto-detected: Vite). Add the custom domain guardianshield.training
in Vercel's project settings and follow its DNS instructions.

NOTE: This is the frontend prototype. Before accepting real customers,
connect a database (e.g. Supabase), Stripe for payments, an email service,
and real authentication. The demo instructor enrollment key is SHIELD.
