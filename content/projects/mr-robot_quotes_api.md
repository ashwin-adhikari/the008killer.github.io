---
title: "Mr. Robot Quotes API"
date: 2026-07-13
draft: false
summary: "An AI-powered quote generator inspired by Mr. Robot, serving dark cinematic quotes as JSON and SVG cards for GitHub READMEs"
tags: ["Node.js", "Express", "Vercel", "OpenRouter", "SVG", "API", "Mr-Robot"]
---

A full-stack AI quote API inspired by the TV series **Mr. Robot**. It generates dark, philosophical, hacker-style quotes and serves them as JSON endpoints and beautiful themed SVG cards — perfect for GitHub profile READMEs.

I've always been a huge fan of **Mr. Robot**. The show's atmosphere — paranoia, isolation, corporate control, and the quiet rebellion of people who see the system for what it really is — stuck with me long after finishing it. Elliot's monologues, Mr. Robot's rage, Whiterose's obsession with time... it all felt like poetry written in code.

This project started as a simple idea: *what if I could generate original quotes that felt like they belonged in that universe?* I wanted something that wasn't just a static list of fan quotes, but a living system — one that could create new lines every day, style them like a terminal, and drop them straight into a GitHub README as a glowing SVG card.

## Features
- AI-generated Mr. Robot style quotes (Elliot, Mr. Robot, Darlene, Whiterose)
- Instant local fallback quotes when AI is slow or unavailable
- Daily quote endpoint (same quote all day)
- Random quote endpoint (fresh every request)
- SVG quote cards with 25+ themes (Dracula, Tokyo Night, Nord, Catppuccin, Cyberpunk, and more)
- Live terminal UI to preview quotes and copy embed URLs
- Custom domain: [quotes.adhikariashwin0.com.np](https://quotes.adhikariashwin0.com.np)
- GitHub Actions auto-updates README with the daily quote

## Tech Stack
- Node.js
- Express.js
- OpenRouter AI
- Vercel (serverless deployment)
- SVG generation with themed CSS
- Cloudflare DNS
- GitHub Actions

## API Endpoints
- `GET /api/quote/random` — Fresh random quote
- `GET /api/quote/daily` — Quote of the day
- `GET /api/quote/svg?theme=mrrobot&mode=daily` — Styled SVG card

## Links
- [Live API](https://quotes.adhikariashwin0.com.np)
- [GitHub Repository](https://github.com/the008killer/mr-robot-quotes-api)