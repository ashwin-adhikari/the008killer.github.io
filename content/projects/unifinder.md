---
title: "UniFinder - University Course Discovery Platform"
date: 2026-09-10
draft: false
summary: "A full-stack web platform helping international students discover, filter, and discuss Bachelor and Master programs across 390+ universities in Germany and Austria"
tags: ["React", "Node.js", "Express", "PostgreSQL", "Socket.io", "Vite", "TailwindCSS", "Neon", "Render", "Vercel"]
---

A full-stack university discovery platform built for international students navigating the overwhelming landscape of German and Austrian higher education. Search through 1,500+ real programs, filter by degree, language, tuition, and subject — then jump into course-specific chat rooms to talk with fellow applicants in real time.

The idea came from a very real frustration. Every year, hundreds of thousands of students from South Asia, Africa, and the Middle East try to find the right program in Germany. The process is brutal - you're bouncing between DAAD, university websites, StudyCheck forums, and WhatsApp groups, trying to piece together whether a program is taught in English, what the actual tuition is, whether you need TestDaF C1 or just B2, and whether anyone else from your country has actually applied there.

I wanted to build the tool I wish I had. Not another generic university ranking site, but a **search engine for courses** — one that lets you type "Embedded Systems" or "Renewable Energy" and instantly see every matching program across 390 universities, with real admission requirements, tuition fees, and a chat room full of students asking the same questions you are.

## Features

- **Smart Search & Filtering** — Full-text keyword search with 400ms client-side debouncing across course names, universities, subjects, and cities. Broad filter sidebar for Degree (Bachelor/Master), Language (English/German/Mixed), University Type (Public/Private/Church), Subject Area, and Max Tuition Fee.
- **Real University Data** — 388 German universities sourced from the official HRK/Destatis registry and 5+ top Austrian institutions (Uni Wien, TU Wien, WU, Innsbruck, MCI). 1,500+ study programs from the DAAD International Programmes dataset.
- **Program & University Profiles** — Detailed course pages with admission requirements, German/English proficiency levels (A1–C2), semester start dates, duration, tuition fees, and direct links to official DAAD course pages. Dynamic university logo fetching with monogram fallbacks.
- **Real-Time Peer Chat** — Socket.io powered chat rooms automatically created for every course. Four discussion sections per room: #General, #Admissions, #Courses & Studies, and #Student Life. WhatsApp-style floating date headers and auto-localized timestamps.
- **User Authentication & Security** — JWT-based registration and login (email or username). Password strength meter with real-time validation. Native RFC 6238 Two-Factor Authentication (2FA) with QR code generation for Google Authenticator/Authy. Forgot password flow with tokenized reset links.
- **Bookmarks & Notifications** — Save courses with a single click from search results or detail pages. Real-time notification bell for new chat messages and @mentions. Persistent bookmark management from the profile dashboard.
- **Mobile-First Responsive Design** — Fully adaptive layout down to 320px viewports with zero horizontal overflow. Custom SVG micro-icon system replacing heavy icon libraries. Shimmer skeleton loaders for smooth perceived performance.

## Tech Stack

- **Frontend:** React 19, Vite, Tailwind CSS, React Router v7, Axios, Socket.io Client
- **Backend:** Node.js, Express.js, Socket.io, JWT, bcryptjs
- **Database:** PostgreSQL (Neon serverless)
- **2FA Engine:** Native Node.js `crypto` (RFC 6238 TOTP — zero external auth dependencies)
- **Email:** Nodemailer (custom domain SMTP via `no-reply@adhikariashwin0.com.np`)
- **Deployment:** Vercel (frontend), Render (backend + WebSockets), Neon (database)
- **Security:** express-rate-limit on auth endpoints, CORS policy, TIMESTAMPTZ for timezone-safe timestamps

## Frontend

The frontend is a single-page application built with Vite and React Router, using URL search parameters for filter state persistence and shareable links. The backend serves REST endpoints for search, filtering, authentication, bookmarks, and notifications, while Socket.io handles real-time chat messaging with section-based room isolation. The database uses indexed queries on subject, degree, language, city, and university type for sub-100ms search response times.

## Data Pipeline

University data was sourced from the official German HRK/Destatis higher education registry (390 institutions) and seeded into PostgreSQL with proper encoding detection (UTF-8/Windows-1252 auto-detection for German umlauts). Course data was ingested from the DAAD International Programmes Kaggle dataset (2,215 records), matched to universities via in-memory fuzzy name resolution, and batch-inserted in groups of 100 for optimal write performance. Chat groups were auto-generated for every university-program combination.

## API Endpoints

- `GET /api/programs?q=&degree=&language=&subject=&city=&uniType=&maxFee=&page=&limit=` — Search and filter courses
- `GET /api/programs/:id` — Course detail with admission requirements
- `GET /api/universities` — List universities with course counts
- `GET /api/universities/:id` — University profile with all programs
- `GET /api/filters` — Available filter options (subjects, cities, states)
- `POST /api/auth/register` — User registration with password strength validation
- `POST /api/auth/login` — Login with email/username + optional 2FA challenge
- `POST /api/2fa/setup` — Generate TOTP secret and QR code
- `POST /api/2fa/verify-setup` — Activate 2FA with authenticator code
- `POST /api/password/forgot` — Request password reset email
- `POST /api/password/reset/:token` — Set new password
- `POST /api/bookmarks/toggle/:programId` — Save or remove a course
- `GET /api/chat/groups/:groupId/messages?section=` — Fetch chat history by section
- `GET /api/notifications` — User notification feed

## Links

- [Live App](https://adhikariashwin0.com.np/unifinder/)
- [GitHub Repository](https://github.com/the008killer/uni-finder)