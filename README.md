# ⚜️ Patrician Study
### A Full-Stack Educational Platform

> Excellence · Knowledge · Progress

Patrician Study is a complete learning management system built with Node.js, Express, MySQL, and the Claude AI API. It supports students, teachers, parents, and administrators — all sharing a real-time MySQL database hosted on Railway.

---

## 🌐 Live Demo

**[patricianstudy.up.railway.app](patricianstudy.up.railway.app)**

| Role | Email | Password |
|------|-------|----------|
| Admin | admin | 1204 |

---

## ✨ Features

- 🤖 **AI Study Assistant** — Powered by Claude, answers questions, explains concepts, and gives feedback
- 🗺️ **AI Study Planner** — Analyses grades and schedules to generate personalised study plans
- 📅 **Study Schedules** — AI-generated timetables based on subjects, topics and exam dates
- 🧠 **Learner** — AI-generated quizzes and flashcards on any topic
- 🏫 **Classrooms** — Teachers create and manage classes, enrol students
- 📋 **Assignments** — Create, submit, and grade assignments with feedback
- 💬 **Messaging** — Direct messages and group chats
- 👥 **Groups** — Study groups with shared chat
- 📊 **Analytics** — Performance tracking, leaderboards, and subject breakdowns
- 🗓️ **Calendar** — Events, exam dates, and assignment deadlines
- 📢 **Announcements** — Platform-wide notices from staff
- 💬 **Forum** — Discussion board with voting and replies
- 📚 **Resource Library** — Share articles, videos, PDFs, and notes
- 👨‍👩‍👧 **Parent Portal** — Monitor children's grades and progress
- 🔔 **Notifications** — Real-time alerts for all platform activity
- 🛡️ **Admin Panel** — Full user management, activity logs, and site settings

---

## 🛠️ Technology Stack

| Technology | Purpose |
|------------|---------|
| Node.js + Express | Backend web server |
| MySQL | Database (hosted on Railway) |
| HTML + CSS + JavaScript | Frontend (single file) |
| Claude API (Anthropic) | AI features |
| Railway.app | Hosting + database |
| GitHub | Version control + auto-deploy |

---

## 🚀 Local Setup

### Prerequisites
- [Node.js](https://nodejs.org) (LTS version)
- [Git](https://git-scm.com)

### Installation

```bash
# Clone the repository
git clone https://github.com/Hagios123/patrician-study-2.git
cd patrician-study-2

# Install dependencies
npm install
```

### Environment Variables

Create a `.env` file in the root folder:

```env
DB_HOST=your_railway_mysql_host
DB_PORT=your_railway_mysql_port
DB_USER=root
DB_PASSWORD=your_railway_mysql_password
DB_NAME=railway
SESSION_SECRET=your_secret_key
CLAUDE_API_KEY=your_anthropic_api_key
PORT=3000
```

### Run Locally

```bash
npm start
```

Visit `http://localhost:3000`

---

## 📁 Project Structure

```
patrician-study/
├── server.js          ← Express backend + API routes
├── package.json       ← Dependencies
├── Procfile           ← Railway startup command
├── .gitignore         ← Excludes .env and node_modules
├── .env               ← Secret credentials (never uploaded)
└── public/
    └── index.html     ← Complete frontend (single file)
```

---

## 🗄️ Database

The MySQL database is hosted on Railway and contains 20 tables:

`users`, `classrooms`, `classroom_students`, `assignments`, `submissions`, `messages`, `groups_table`, `group_members`, `friends`, `schedules`, `quizzes`, `grades`, `notifications`, `announcements`, `forum_posts`, `forum_replies`, `resources`, `events`, `parent_links`, `activity_log`

---

## 🚢 Deployment

This project auto-deploys to Railway whenever code is pushed to the `main` branch on GitHub.

```bash
# Push updates
git add .
git commit -m "your message"
git push
```

Railway detects the push and redeploys automatically.

---

## 👤 User Roles

| Role | Access |
|------|--------|
| **Admin** | Full platform control, user management, activity logs |
| **Teacher** | Classrooms, assignments, grading, announcements |
| **Student** | Schedules, quizzes, assignments, AI tools, messaging |
| **Parent** | View children's grades, assignments, and progress |

---

## 🔑 API Keys Required

- **Anthropic API Key** — for AI features → [console.anthropic.com](https://console.anthropic.com)

---

## 📄 License

This project was built as a college mini-project.
