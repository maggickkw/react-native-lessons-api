package main

import (
	"database/sql"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	_ "modernc.org/sqlite"
)

type Note struct {
	ID         int       `json:"id"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	Category   string    `json:"category"`
	IsFavorite bool      `json:"isFavorite"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	UserID     int       `json:"userId"`
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Name     string `json:"name"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

var db *sql.DB

// Simple token storage (use proper JWT in production)
var validTokens = make(map[string]int) // token -> userID

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))
	app.Use(logger.New())

	// Auth routes
	app.Post("/api/auth/register", register)
	app.Post("/api/auth/login", login)

	// Protected routes
	app.Use("/api/notes", authMiddleware)
	app.Get("/api/notes", getNotes)
	app.Post("/api/notes", createNote)
	app.Get("/api/notes/:id", getNote)
	app.Put("/api/notes/:id", updateNote)
	app.Delete("/api/notes/:id", deleteNote)

	app.Post("/favorites", addFavorite)
	app.Get("/favorites/:userId", getFavorites)
	app.Delete("/favorites/:userId/:noteId", removeFavorite)

	// Health check
	app.Get("/api/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now(),
		})
	})

	log.Printf("Server starting on port 3001...")
	log.Fatal(app.Listen(":3001"))
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./notes.db")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Create tables
	createTables()

	// Seed initial data
	seedData()
}

func createTables() {
	// Users table
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Notes table
	noteTable := `
	CREATE TABLE IF NOT EXISTS notes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		content TEXT,
		category TEXT DEFAULT 'General',
		is_favorite BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);`

	favoritesTable := `
    CREATE TABLE IF NOT EXISTS favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        note_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(note_id) REFERENCES notes(id),
        UNIQUE(user_id, note_id) -- prevents duplicate favorites
    )
`
	if _, err := db.Exec(favoritesTable); err != nil {
		log.Fatal("Failed to create favorites table:", err)
	}

	if _, err := db.Exec(userTable); err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	if _, err := db.Exec(noteTable); err != nil {
		log.Fatal("Failed to create notes table:", err)
	}
}

func seedData() {
	// Check if demo user already exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", "demo@example.com").Scan(&count)
	if err != nil {
		log.Printf("Error checking for demo user: %v", err)
		return
	}

	if count > 0 {
		return // Demo user already exists
	}

	// Insert demo user
	result, err := db.Exec(
		"INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
		"demo@example.com", "password123", "Demo User",
	)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
		return
	}

	userID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting demo user ID: %v", err)
		return
	}

	// Insert sample notes
	sampleNotes := [][]interface{}{
		{"Welcome to Notes", "This is your first note!", "General", true, userID},
		{"React Native Tips", "Remember to use hooks properly", "Development", false, userID},
		{"Shopping List", "Milk, Bread, Eggs", "Personal", true, userID},
	}

	for _, note := range sampleNotes {
		_, err := db.Exec(
			"INSERT INTO notes (title, content, category, is_favorite, user_id) VALUES (?, ?, ?, ?, ?)",
			note[0], note[1], note[2], note[3], note[4],
		)
		if err != nil {
			log.Printf("Error creating sample note: %v", err)
		}
	}

	log.Println("Database seeded with demo user and sample notes")
}

func authMiddleware(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	if token == "" {
		return c.Status(401).JSON(fiber.Map{"error": "Authorization token required"})
	}

	// Remove "Bearer " prefix if present
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	userID, exists := validTokens[token]
	if !exists {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid token"})
	}

	c.Locals("userID", userID)
	return c.Next()
}

func register(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email, password, and name are required"})
	}

	// Check if user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&count)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	if count > 0 {
		return c.Status(400).JSON(fiber.Map{"error": "User already exists"})
	}

	// Create user
	result, err := db.Exec(
		"INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
		req.Email, req.Password, req.Name,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create user"})
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	user := User{
		ID:    int(userID),
		Email: req.Email,
		Name:  req.Name,
	}

	// Generate token
	token := "token_" + strconv.FormatInt(userID, 10) + "_" + strconv.FormatInt(time.Now().Unix(), 10)
	validTokens[token] = int(userID)

	return c.JSON(AuthResponse{
		Token: token,
		User:  user,
	})
}

func login(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email and password are required"})
	}

	// Find user
	var user User
	err := db.QueryRow(
		"SELECT id, email, name FROM users WHERE email = ? AND password = ?",
		req.Email, req.Password,
	).Scan(&user.ID, &user.Email, &user.Name)

	if err == sql.ErrNoRows {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	// Generate token
	token := "token_" + strconv.Itoa(user.ID) + "_" + strconv.FormatInt(time.Now().Unix(), 10)
	validTokens[token] = user.ID

	return c.JSON(AuthResponse{
		Token: token,
		User:  user,
	})
}

func getNotes(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	rows, err := db.Query(`
		SELECT id, title, content, category, is_favorite, created_at, updated_at, user_id 
		FROM notes WHERE user_id = ? ORDER BY updated_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var note Note
		err := rows.Scan(
			&note.ID, &note.Title, &note.Content, &note.Category,
			&note.IsFavorite, &note.CreatedAt, &note.UpdatedAt, &note.UserID,
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database scan error"})
		}
		notes = append(notes, note)
	}

	if notes == nil {
		notes = []Note{} // Return empty array instead of null
	}

	return c.JSON(fiber.Map{
		"data":  notes,
		"total": len(notes),
	})
}

func createNote(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	var note Note
	if err := c.BodyParser(&note); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if note.Title == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Title is required"})
	}

	if note.Category == "" {
		note.Category = "General"
	}

	result, err := db.Exec(`
		INSERT INTO notes (title, content, category, is_favorite, user_id) 
		VALUES (?, ?, ?, ?, ?)
	`, note.Title, note.Content, note.Category, note.IsFavorite, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	noteID, err := result.LastInsertId()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get note ID"})
	}

	// Fetch the created note with timestamps
	var createdNote Note
	err = db.QueryRow(`
		SELECT id, title, content, category, is_favorite, created_at, updated_at, user_id 
		FROM notes WHERE id = ?
	`, noteID).Scan(
		&createdNote.ID, &createdNote.Title, &createdNote.Content, &createdNote.Category,
		&createdNote.IsFavorite, &createdNote.CreatedAt, &createdNote.UpdatedAt, &createdNote.UserID,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch created note"})
	}

	return c.Status(201).JSON(fiber.Map{
		"message": "Note created successfully",
		"data":    createdNote,
	})
}

func getNote(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var note Note
	err = db.QueryRow(`
		SELECT id, title, content, category, is_favorite, created_at, updated_at, user_id 
		FROM notes WHERE id = ? AND user_id = ?
	`, id, userID).Scan(
		&note.ID, &note.Title, &note.Content, &note.Category,
		&note.IsFavorite, &note.CreatedAt, &note.UpdatedAt, &note.UserID,
	)

	if err == sql.ErrNoRows {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(fiber.Map{"data": note})
}

func updateNote(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var updateData Note
	if err := c.BodyParser(&updateData); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Check if note exists and belongs to user
	var exists int
	err = db.QueryRow("SELECT COUNT(*) FROM notes WHERE id = ? AND user_id = ?", id, userID).Scan(&exists)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	if exists == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Update note
	_, err = db.Exec(`
		UPDATE notes 
		SET title = ?, content = ?, category = ?, is_favorite = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND user_id = ?
	`, updateData.Title, updateData.Content, updateData.Category, updateData.IsFavorite, id, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update note"})
	}

	// Fetch updated note
	var updatedNote Note
	err = db.QueryRow(`
		SELECT id, title, content, category, is_favorite, created_at, updated_at, user_id 
		FROM notes WHERE id = ? AND user_id = ?
	`, id, userID).Scan(
		&updatedNote.ID, &updatedNote.Title, &updatedNote.Content, &updatedNote.Category,
		&updatedNote.IsFavorite, &updatedNote.CreatedAt, &updatedNote.UpdatedAt, &updatedNote.UserID,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch updated note"})
	}

	return c.JSON(fiber.Map{
		"message": "Note updated successfully",
		"data":    updatedNote,
	})
}

func deleteNote(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	result, err := db.Exec("DELETE FROM notes WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete note"})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	if rowsAffected == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	return c.JSON(fiber.Map{"message": "Note deleted successfully"})
}

func addFavorite(c *fiber.Ctx) error {
	type req struct {
		UserID int `json:"user_id"`
		NoteID int `json:"note_id"`
	}
	var body req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	_, err := db.Exec("INSERT OR IGNORE INTO favorites (user_id, note_id) VALUES (?, ?)", body.UserID, body.NoteID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to add favorite"})
	}

	return c.JSON(fiber.Map{"message": "Note favorited"})
}

func getFavorites(c *fiber.Ctx) error {
	userId := c.Params("userId")

	rows, err := db.Query(`
        SELECT notes.id, notes.title, notes.content, notes.created_at
        FROM notes
        JOIN favorites ON notes.id = favorites.note_id
        WHERE favorites.user_id = ?
    `, userId)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch favorites"})
	}
	defer rows.Close()

	var notes []fiber.Map
	for rows.Next() {
		var id int
		var title, content string
		var createdAt string
		rows.Scan(&id, &title, &content, &createdAt)
		notes = append(notes, fiber.Map{
			"id": id, "title": title, "content": content, "created_at": createdAt,
		})
	}

	return c.JSON(notes)
}

func removeFavorite(c *fiber.Ctx) error {
	userId := c.Params("userId")
	noteId := c.Params("noteId")

	_, err := db.Exec("DELETE FROM favorites WHERE user_id = ? AND note_id = ?", userId, noteId)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to remove favorite"})
	}

	return c.JSON(fiber.Map{"message": "Favorite removed"})
}
