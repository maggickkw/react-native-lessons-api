package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	IsPublic   bool      `json:"isPublic"`
	ImageUrls  []string  `json:"imageUrls"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	UserID     int       `json:"userId"`
	Author     *User     `json:"author,omitempty"`
	LikesCount int       `json:"likesCount"`
	IsLiked    bool      `json:"isLikedByCurrentUser"`
}

type User struct {
	ID             int    `json:"id"`
	Email          string `json:"email"`
	Password       string `json:"-"`
	Name           string `json:"name"`
	ProfilePicture string `json:"profilePicture"`
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

type LikeRequest struct {
	NoteID int `json:"noteId"`
}

type LikeResponse struct {
	NoteID     int    `json:"noteId"`
	LikesCount int    `json:"likesCount"`
	IsLiked    bool   `json:"isLiked"`
	Message    string `json:"message"`
}

type PushTokenRequest struct {
	Token    string `json:"token"`
	Platform string `json:"platform"`
}

type PushNotificationRequest struct {
	UserID  int    `json:"userId"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

var db *sql.DB

// Simple token storage (use proper JWT in production)
var validTokens = make(map[string]int) // token -> userID

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Create uploads directory
	os.MkdirAll("./uploads", 0755)

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
	app.Use("/api/social", authMiddleware)
	app.Use("/api/upload", authMiddleware)
	app.Use("/api/user", authMiddleware)
	app.Use("/api/push", authMiddleware)

	// Notes routes
	app.Get("/api/notes", getNotes)
	app.Post("/api/notes", createNote)
	app.Get("/api/notes/:id", getNote)
	app.Put("/api/notes/:id", updateNote)
	app.Delete("/api/notes/:id", deleteNote)

	// Social routes
	app.Get("/api/social/feed", getSocialFeed)
	app.Post("/api/social/notes/:id/like", toggleLike)
	app.Get("/api/social/notes/:id/likes", getNoteLikes)

	// Upload routes
	app.Post("/api/upload/image", uploadImage)
	app.Static("/uploads", "./uploads")

	// User profile routes
	app.Put("/api/user/profile", updateProfile)
	app.Get("/api/user/:id/profile", getUserProfile)

	// Push notification routes
	app.Post("/api/push/register", registerPushToken)
	app.Post("/api/push/unregister", unregisterPushToken)
	app.Post("/api/push/send", sendPushNotification)

	// Favorites routes
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
	// Users table with profile picture
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		name TEXT NOT NULL,
		profile_picture TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Notes table with public flag and image URLs
	noteTable := `
	CREATE TABLE IF NOT EXISTS notes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		content TEXT,
		category TEXT DEFAULT 'General',
		is_favorite BOOLEAN DEFAULT FALSE,
		is_public BOOLEAN DEFAULT FALSE,
		image_urls TEXT, -- JSON string of image URLs
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);`

	// Favorites table
	favoritesTable := `
	CREATE TABLE IF NOT EXISTS favorites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		note_id INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id),
		FOREIGN KEY(note_id) REFERENCES notes(id),
		UNIQUE(user_id, note_id)
	);`

	// Likes table
	likesTable := `
	CREATE TABLE IF NOT EXISTS likes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		note_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
		FOREIGN KEY (note_id) REFERENCES notes (id) ON DELETE CASCADE,
		UNIQUE(user_id, note_id)
	);`

	// Push tokens table
	pushTokensTable := `
	CREATE TABLE IF NOT EXISTS push_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT NOT NULL,
		platform TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
		UNIQUE(user_id, platform)
	);`

	tables := []string{userTable, noteTable, favoritesTable, likesTable, pushTokensTable}
	for _, table := range tables {
		if _, err := db.Exec(table); err != nil {
			log.Fatal("Failed to create table:", err)
		}
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

	// Insert demo users
	demoUsers := [][]interface{}{
		{"demo@example.com", "password123", "Demo User"},
		{"alice@example.com", "password123", "Alice Johnson"},
		{"bob@example.com", "password123", "Bob Smith"},
	}

	var userIDs []int64
	for _, user := range demoUsers {
		result, err := db.Exec(
			"INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
			user[0], user[1], user[2],
		)
		if err != nil {
			log.Printf("Error creating demo user: %v", err)
			continue
		}

		userID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Error getting demo user ID: %v", err)
			continue
		}
		userIDs = append(userIDs, userID)
	}

	// Insert sample notes (mix of public and private)
	sampleNotes := [][]interface{}{
		{"Welcome to Notes", "This is your first note!", "General", true, false, userIDs[0]},
		{"React Native Tips", "Remember to use hooks properly", "Development", false, true, userIDs[0]},
		{"Coffee Recipe", "My favorite morning brew technique", "Personal", true, true, userIDs[1]},
		{"Travel Plans", "Summer vacation ideas", "Travel", false, true, userIDs[1]},
		{"Book Recommendations", "Great reads for developers", "Learning", false, true, userIDs[2]},
		{"Weekend Project", "Building a mobile app", "Development", true, true, userIDs[2]},
	}

	for _, note := range sampleNotes {
		_, err := db.Exec(
			"INSERT INTO notes (title, content, category, is_favorite, is_public, user_id) VALUES (?, ?, ?, ?, ?, ?)",
			note[0], note[1], note[2], note[3], note[4], note[5],
		)
		if err != nil {
			log.Printf("Error creating sample note: %v", err)
		}
	}

	log.Println("Database seeded with demo users and sample notes")
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
	// Handle multipart form data for file upload
	email := c.FormValue("email")
	password := c.FormValue("password")
	name := c.FormValue("name")

	if email == "" || password == "" || name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email, password, and name are required"})
	}

	// Check if user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	if count > 0 {
		return c.Status(400).JSON(fiber.Map{"error": "User already exists"})
	}

	// Handle profile picture upload
	var profilePictureURL string
	file, err := c.FormFile("profilePicture")
	if err == nil && file != nil {
		// Validate file type
		allowedTypes := map[string]bool{
			"image/jpeg": true,
			"image/jpg":  true,
			"image/png":  true,
			"image/gif":  true,
		}

		if !allowedTypes[file.Header.Get("Content-Type")] {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid file type. Only JPEG, PNG, and GIF are allowed"})
		}

		// Validate file size (5MB max)
		if file.Size > 5*1024*1024 {
			return c.Status(400).JSON(fiber.Map{"error": "File too large. Maximum size is 5MB"})
		}

		// Generate unique filename
		ext := filepath.Ext(file.Filename)
		filename := fmt.Sprintf("profile_%d_%d%s", time.Now().Unix(), time.Now().UnixNano(), ext)

		// Save file
		err = c.SaveFile(file, fmt.Sprintf("./uploads/%s", filename))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to save profile picture"})
		}

		profilePictureURL = fmt.Sprintf("/uploads/%s", filename)
	}

	// Create user
	result, err := db.Exec(
		"INSERT INTO users (email, password, name, profile_picture) VALUES (?, ?, ?, ?)",
		email, password, name, profilePictureURL,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create user"})
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	user := User{
		ID:             int(userID),
		Email:          email,
		Name:           name,
		ProfilePicture: profilePictureURL,
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
		"SELECT id, email, name, COALESCE(profile_picture, '') FROM users WHERE email = ? AND password = ?",
		req.Email, req.Password,
	).Scan(&user.ID, &user.Email, &user.Name, &user.ProfilePicture)

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
		SELECT n.id, n.title, n.content, n.category, n.is_favorite, n.is_public, 
		       COALESCE(n.image_urls, '[]'), n.created_at, n.updated_at, n.user_id,
		       COUNT(l.id) as likes_count
		FROM notes n
		LEFT JOIN likes l ON n.id = l.note_id
		WHERE n.user_id = ? 
		GROUP BY n.id
		ORDER BY n.updated_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var note Note
		var imageUrlsJSON string
		err := rows.Scan(
			&note.ID, &note.Title, &note.Content, &note.Category,
			&note.IsFavorite, &note.IsPublic, &imageUrlsJSON, &note.CreatedAt,
			&note.UpdatedAt, &note.UserID, &note.LikesCount,
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database scan error"})
		}

		// Parse image URLs
		json.Unmarshal([]byte(imageUrlsJSON), &note.ImageUrls)
		if note.ImageUrls == nil {
			note.ImageUrls = []string{}
		}

		// Check if current user liked this note
		note.IsLiked = checkUserLikedNote(userID, note.ID)

		notes = append(notes, note)
	}

	if notes == nil {
		notes = []Note{}
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

	// Convert image URLs to JSON
	imageUrlsJSON := "[]"
	if note.ImageUrls != nil && len(note.ImageUrls) > 0 {
		jsonBytes, _ := json.Marshal(note.ImageUrls)
		imageUrlsJSON = string(jsonBytes)
	}

	result, err := db.Exec(`
		INSERT INTO notes (title, content, category, is_favorite, is_public, image_urls, user_id) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, note.Title, note.Content, note.Category, note.IsFavorite, note.IsPublic, imageUrlsJSON, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	noteID, err := result.LastInsertId()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get note ID"})
	}

	// Fetch the created note
	createdNote, err := fetchNoteWithDetails(int(noteID), userID)
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

	note, err := fetchNoteWithDetails(id, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
		}
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

	// Convert image URLs to JSON
	imageUrlsJSON := "[]"
	if updateData.ImageUrls != nil && len(updateData.ImageUrls) > 0 {
		jsonBytes, _ := json.Marshal(updateData.ImageUrls)
		imageUrlsJSON = string(jsonBytes)
	}

	// Update note
	_, err = db.Exec(`
		UPDATE notes 
		SET title = ?, content = ?, category = ?, is_favorite = ?, is_public = ?, 
		    image_urls = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND user_id = ?
	`, updateData.Title, updateData.Content, updateData.Category, updateData.IsFavorite,
		updateData.IsPublic, imageUrlsJSON, id, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update note"})
	}

	// Fetch updated note
	updatedNote, err := fetchNoteWithDetails(id, userID)
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

// Social Feed Functions
func getSocialFeed(c *fiber.Ctx) error {
	currentUserID := c.Locals("userID").(int)

	// Get limit and offset for pagination
	limit := c.QueryInt("limit", 20)
	offset := c.QueryInt("offset", 0)

	rows, err := db.Query(`
		SELECT n.id, n.title, n.content, n.category, n.is_favorite, n.is_public,
		       COALESCE(n.image_urls, '[]'), n.created_at, n.updated_at, n.user_id,
		       u.name, COALESCE(u.profile_picture, ''),
		       COUNT(l.id) as likes_count
		FROM notes n
		JOIN users u ON n.user_id = u.id
		LEFT JOIN likes l ON n.id = l.note_id
		WHERE n.is_public = TRUE
		GROUP BY n.id
		ORDER BY n.created_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var note Note
		var imageUrlsJSON string
		var author User

		err := rows.Scan(
			&note.ID, &note.Title, &note.Content, &note.Category,
			&note.IsFavorite, &note.IsPublic, &imageUrlsJSON, &note.CreatedAt,
			&note.UpdatedAt, &note.UserID, &author.Name, &author.ProfilePicture,
			&note.LikesCount,
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database scan error"})
		}

		// Parse image URLs
		json.Unmarshal([]byte(imageUrlsJSON), &note.ImageUrls)
		if note.ImageUrls == nil {
			note.ImageUrls = []string{}
		}

		// Set author info
		author.ID = note.UserID
		note.Author = &author

		// Check if current user liked this note
		note.IsLiked = checkUserLikedNote(currentUserID, note.ID)

		notes = append(notes, note)
	}

	if notes == nil {
		notes = []Note{}
	}

	return c.JSON(fiber.Map{
		"data":   notes,
		"total":  len(notes),
		"limit":  limit,
		"offset": offset,
	})
}

func toggleLike(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)
	noteID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	// Check if note exists and is public
	var noteOwnerID int
	var isPublic bool
	err = db.QueryRow("SELECT user_id, is_public FROM notes WHERE id = ?", noteID).Scan(&noteOwnerID, &isPublic)
	if err == sql.ErrNoRows {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	if !isPublic {
		return c.Status(403).JSON(fiber.Map{"error": "Cannot like private notes"})
	}

	// Check if user already liked this note
	var likeExists int
	err = db.QueryRow("SELECT COUNT(*) FROM likes WHERE user_id = ? AND note_id = ?", userID, noteID).Scan(&likeExists)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	var message string
	var isLiked bool

	if likeExists > 0 {
		// Unlike the note
		_, err = db.Exec("DELETE FROM likes WHERE user_id = ? AND note_id = ?", userID, noteID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to unlike note"})
		}
		message = "Note unliked successfully"
		isLiked = false
	} else {
		// Like the note
		_, err = db.Exec("INSERT INTO likes (user_id, note_id) VALUES (?, ?)", userID, noteID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to like note"})
		}
		message = "Note liked successfully"
		isLiked = true

		// Send push notification to note owner (if not liking own note)
		if noteOwnerID != userID {
			go sendLikeNotification(noteOwnerID, userID, noteID)
		}
	}

	// Get updated like count
	var likesCount int
	err = db.QueryRow("SELECT COUNT(*) FROM likes WHERE note_id = ?", noteID).Scan(&likesCount)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get like count"})
	}

	return c.JSON(LikeResponse{
		NoteID:     noteID,
		LikesCount: likesCount,
		IsLiked:    isLiked,
		Message:    message,
	})
}

func getNoteLikes(c *fiber.Ctx) error {
	noteID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	rows, err := db.Query(`
		SELECT u.id, u.name, COALESCE(u.profile_picture, ''), l.created_at
		FROM likes l
		JOIN users u ON l.user_id = u.id
		WHERE l.note_id = ?
		ORDER BY l.created_at DESC
	`, noteID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	var likes []fiber.Map
	var likesCount int
	for rows.Next() {
		var userID int
		var userName, profilePicture string
		var createdAt time.Time

		err := rows.Scan(&userID, &userName, &profilePicture, &createdAt)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database scan error"})
		}

		likes = append(likes, fiber.Map{
			"userId":         userID,
			"userName":       userName,
			"profilePicture": profilePicture,
			"likedAt":        createdAt,
		})
		likesCount++
	}

	if likes == nil {
		likes = []fiber.Map{}
	}

	return c.JSON(fiber.Map{"data": likes,
		"likesCount": likesCount,
	})
}

// Image Upload Functions
func uploadImage(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No image file provided"})
	}

	// Validate file type
	allowedTypes := map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/gif":  true,
		"image/webp": true,
	}

	if !allowedTypes[file.Header.Get("Content-Type")] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed"})
	}

	// Validate file size (10MB max)
	if file.Size > 10*1024*1024 {
		return c.Status(400).JSON(fiber.Map{"error": "File too large. Maximum size is 10MB"})
	}

	// Generate unique filename
	ext := filepath.Ext(file.Filename)
	filename := fmt.Sprintf("note_%d_%d_%d%s", userID, time.Now().Unix(), time.Now().UnixNano(), ext)

	// Save file
	err = c.SaveFile(file, fmt.Sprintf("./uploads/%s", filename))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save image"})
	}

	imageURL := fmt.Sprintf("/uploads/%s", filename)

	return c.JSON(fiber.Map{
		"message":  "Image uploaded successfully",
		"imageUrl": imageURL,
	})
}

// User Profile Functions
func updateProfile(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	// Handle both JSON and multipart form data
	var name, email, currentPassword, newPassword string
	var profilePictureURL string

	// Check if it's multipart form data (for file upload)
	if c.Get("Content-Type") != "" && strings.Contains(c.Get("Content-Type"), "multipart/form-data") {
		name = c.FormValue("name")
		email = c.FormValue("email")
		currentPassword = c.FormValue("currentPassword")
		newPassword = c.FormValue("newPassword")

		// Handle profile picture upload
		file, err := c.FormFile("profilePicture")
		if err == nil && file != nil {
			// Validate file type and size (same as in register)
			allowedTypes := map[string]bool{
				"image/jpeg": true,
				"image/jpg":  true,
				"image/png":  true,
				"image/gif":  true,
			}

			if !allowedTypes[file.Header.Get("Content-Type")] {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid file type"})
			}

			if file.Size > 5*1024*1024 {
				return c.Status(400).JSON(fiber.Map{"error": "File too large. Maximum size is 5MB"})
			}

			// Generate unique filename
			ext := filepath.Ext(file.Filename)
			filename := fmt.Sprintf("profile_%d_%d%s", userID, time.Now().Unix(), ext)

			// Save file
			err = c.SaveFile(file, fmt.Sprintf("./uploads/%s", filename))
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to save profile picture"})
			}

			profilePictureURL = fmt.Sprintf("/uploads/%s", filename)
		}
	} else {
		// Handle JSON request
		var req struct {
			Name            string `json:"name"`
			Email           string `json:"email"`
			CurrentPassword string `json:"currentPassword,omitempty"`
			NewPassword     string `json:"newPassword,omitempty"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
		}

		name = req.Name
		email = req.Email
		currentPassword = req.CurrentPassword
		newPassword = req.NewPassword
	}

	// Get current user data
	var currentUser User
	err := db.QueryRow(
		"SELECT id, email, password, name, COALESCE(profile_picture, '') FROM users WHERE id = ?",
		userID,
	).Scan(&currentUser.ID, &currentUser.Email, &currentUser.Password, &currentUser.Name, &currentUser.ProfilePicture)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user data"})
	}

	// Use current values if not provided
	if name == "" {
		name = currentUser.Name
	}
	if email == "" {
		email = currentUser.Email
	}
	if profilePictureURL == "" {
		profilePictureURL = currentUser.ProfilePicture
	}

	// Handle password change
	password := currentUser.Password
	if newPassword != "" {
		if currentPassword == "" {
			return c.Status(400).JSON(fiber.Map{"error": "Current password required to change password"})
		}
		if currentPassword != currentUser.Password {
			return c.Status(400).JSON(fiber.Map{"error": "Current password is incorrect"})
		}
		password = newPassword
	}

	// Check if email is already taken by another user
	if email != currentUser.Email {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", email, userID).Scan(&count)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database error"})
		}
		if count > 0 {
			return c.Status(400).JSON(fiber.Map{"error": "Email already taken"})
		}
	}

	// Update user
	_, err = db.Exec(
		"UPDATE users SET email = ?, password = ?, name = ?, profile_picture = ? WHERE id = ?",
		email, password, name, profilePictureURL, userID,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update profile"})
	}

	// Return updated user data
	updatedUser := User{
		ID:             userID,
		Email:          email,
		Name:           name,
		ProfilePicture: profilePictureURL,
	}

	return c.JSON(fiber.Map{
		"message": "Profile updated successfully",
		"user":    updatedUser,
	})
}

func getUserProfile(c *fiber.Ctx) error {
	userID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var user User
	err = db.QueryRow(
		"SELECT id, email, name, COALESCE(profile_picture, '') FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Email, &user.Name, &user.ProfilePicture)

	if err == sql.ErrNoRows {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	// Get user's public notes count
	var notesCount int
	err = db.QueryRow("SELECT COUNT(*) FROM notes WHERE user_id = ? AND is_public = TRUE", userID).Scan(&notesCount)
	if err != nil {
		notesCount = 0
	}

	// Get user's total likes received
	var likesReceived int
	err = db.QueryRow(`
		SELECT COUNT(l.id) 
		FROM likes l 
		JOIN notes n ON l.note_id = n.id 
		WHERE n.user_id = ?
	`, userID).Scan(&likesReceived)
	if err != nil {
		likesReceived = 0
	}

	return c.JSON(fiber.Map{
		"data": fiber.Map{
			"user":          user,
			"publicNotes":   notesCount,
			"likesReceived": likesReceived,
		},
	})
}

// Push Notification Functions
func registerPushToken(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	var req PushTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Token == "" || req.Platform == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Token and platform are required"})
	}

	// Insert or update push token
	_, err := db.Exec(`
		INSERT INTO push_tokens (user_id, token, platform) 
		VALUES (?, ?, ?)
		ON CONFLICT(user_id, platform) DO UPDATE SET 
		token = excluded.token,
		created_at = CURRENT_TIMESTAMP
	`, userID, req.Token, req.Platform)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to register push token"})
	}

	return c.JSON(fiber.Map{
		"message": "Push token registered successfully",
	})
}

func unregisterPushToken(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	var req struct {
		Platform string `json:"platform"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	_, err := db.Exec("DELETE FROM push_tokens WHERE user_id = ? AND platform = ?", userID, req.Platform)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to unregister push token"})
	}

	return c.JSON(fiber.Map{
		"message": "Push token unregistered successfully",
	})
}

func sendPushNotification(c *fiber.Ctx) error {
	var req PushNotificationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Get user's push tokens
	rows, err := db.Query("SELECT token, platform FROM push_tokens WHERE user_id = ?", req.UserID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get push tokens"})
	}
	defer rows.Close()

	var sentCount int
	for rows.Next() {
		var token, platform string
		if err := rows.Scan(&token, &platform); err != nil {
			continue
		}

		// In a real implementation, you would send to FCM/APNS here
		// For now, just log the notification
		log.Printf("Would send push notification to %s (%s): %s - %s", token, platform, req.Title, req.Message)
		sentCount++
	}

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Push notification sent to %d devices", sentCount),
		"sent":    sentCount,
	})
}

// Favorites Functions
func addFavorite(c *fiber.Ctx) error {
	userID := c.Locals("userID").(int)

	var req struct {
		NoteID int `json:"noteId"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Check if note exists and is accessible to user
	var noteOwnerID int
	var isPublic bool
	err := db.QueryRow("SELECT user_id, is_public FROM notes WHERE id = ?", req.NoteID).Scan(&noteOwnerID, &isPublic)
	if err == sql.ErrNoRows {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	// User can favorite their own notes or public notes
	if noteOwnerID != userID && !isPublic {
		return c.Status(403).JSON(fiber.Map{"error": "Cannot favorite private notes from other users"})
	}

	// Add to favorites
	_, err = db.Exec(
		"INSERT INTO favorites (user_id, note_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
		userID, req.NoteID,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to add favorite"})
	}

	return c.JSON(fiber.Map{
		"message": "Note added to favorites",
	})
}

func getFavorites(c *fiber.Ctx) error {
	userID, err := strconv.Atoi(c.Params("userId"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	currentUserID := c.Locals("userID").(int)

	// Users can only see their own favorites
	if userID != currentUserID {
		return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
	}

	rows, err := db.Query(`
		SELECT n.id, n.title, n.content, n.category, n.is_favorite, n.is_public,
		       COALESCE(n.image_urls, '[]'), n.created_at, n.updated_at, n.user_id,
		       u.name, COALESCE(u.profile_picture, ''),
		       COUNT(l.id) as likes_count, f.created_at as favorited_at
		FROM favorites f
		JOIN notes n ON f.note_id = n.id
		JOIN users u ON n.user_id = u.id
		LEFT JOIN likes l ON n.id = l.note_id
		WHERE f.user_id = ?
		GROUP BY n.id
		ORDER BY f.created_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	var favorites []fiber.Map
	for rows.Next() {
		var note Note
		var imageUrlsJSON string
		var author User
		var favoritedAt time.Time

		err := rows.Scan(
			&note.ID, &note.Title, &note.Content, &note.Category,
			&note.IsFavorite, &note.IsPublic, &imageUrlsJSON, &note.CreatedAt,
			&note.UpdatedAt, &note.UserID, &author.Name, &author.ProfilePicture,
			&note.LikesCount, &favoritedAt,
		)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database scan error"})
		}

		// Parse image URLs
		json.Unmarshal([]byte(imageUrlsJSON), &note.ImageUrls)
		if note.ImageUrls == nil {
			note.ImageUrls = []string{}
		}

		// Set author info
		author.ID = note.UserID
		note.Author = &author

		// Check if current user liked this note
		note.IsLiked = checkUserLikedNote(currentUserID, note.ID)

		favorites = append(favorites, fiber.Map{
			"note":        note,
			"favoritedAt": favoritedAt,
		})
	}

	if favorites == nil {
		favorites = []fiber.Map{}
	}

	return c.JSON(fiber.Map{
		"data":  favorites,
		"total": len(favorites),
	})
}

func removeFavorite(c *fiber.Ctx) error {
	userID, err := strconv.Atoi(c.Params("userId"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	noteID, err := strconv.Atoi(c.Params("noteId"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	currentUserID := c.Locals("userID").(int)

	// Users can only remove their own favorites
	if userID != currentUserID {
		return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
	}

	result, err := db.Exec("DELETE FROM favorites WHERE user_id = ? AND note_id = ?", userID, noteID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to remove favorite"})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	if rowsAffected == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Favorite not found"})
	}

	return c.JSON(fiber.Map{
		"message": "Note removed from favorites",
	})
}

// Helper Functions
func fetchNoteWithDetails(noteID, currentUserID int) (Note, error) {
	var note Note
	var imageUrlsJSON string

	err := db.QueryRow(`
		SELECT n.id, n.title, n.content, n.category, n.is_favorite, n.is_public,
		       COALESCE(n.image_urls, '[]'), n.created_at, n.updated_at, n.user_id,
		       COUNT(l.id) as likes_count
		FROM notes n
		LEFT JOIN likes l ON n.id = l.note_id
		WHERE n.id = ? AND n.user_id = ?
		GROUP BY n.id
	`, noteID, currentUserID).Scan(
		&note.ID, &note.Title, &note.Content, &note.Category,
		&note.IsFavorite, &note.IsPublic, &imageUrlsJSON, &note.CreatedAt,
		&note.UpdatedAt, &note.UserID, &note.LikesCount,
	)

	if err != nil {
		return note, err
	}

	// Parse image URLs
	json.Unmarshal([]byte(imageUrlsJSON), &note.ImageUrls)
	if note.ImageUrls == nil {
		note.ImageUrls = []string{}
	}

	// Check if current user liked this note
	note.IsLiked = checkUserLikedNote(currentUserID, noteID)

	return note, nil
}

func checkUserLikedNote(userID, noteID int) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM likes WHERE user_id = ? AND note_id = ?", userID, noteID).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func sendLikeNotification(noteOwnerID, likerUserID, noteID int) {
	// Get liker's name
	var likerName string
	err := db.QueryRow("SELECT name FROM users WHERE id = ?", likerUserID).Scan(&likerName)
	if err != nil {
		log.Printf("Error getting liker name: %v", err)
		return
	}

	// Get note title
	var noteTitle string
	err = db.QueryRow("SELECT title FROM notes WHERE id = ?", noteID).Scan(&noteTitle)
	if err != nil {
		log.Printf("Error getting note title: %v", err)
		return
	}

	// Get note owner's push tokens
	rows, err := db.Query("SELECT token, platform FROM push_tokens WHERE user_id = ?", noteOwnerID)
	if err != nil {
		log.Printf("Error getting push tokens: %v", err)
		return
	}
	defer rows.Close()

	title := "Someone liked your note!"
	message := fmt.Sprintf("%s liked your note '%s'", likerName, noteTitle)

	for rows.Next() {
		var token, platform string
		if err := rows.Scan(&token, &platform); err != nil {
			continue
		}

		// In a real implementation, you would send to FCM/APNS here
		log.Printf("Would send like notification to %s (%s): %s - %s", token, platform, title, message)
	}
}
