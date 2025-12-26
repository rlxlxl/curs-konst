#ifndef QUERIES_H
#define QUERIES_H

/**
 * Файл с SQL запросами для работы с базой данных
 * Все запросы используют параметризованный подход для защиты от SQL инъекций
 */

// SQL запросы для работы с пользователями
namespace UserQueries {
    // Получить роль пользователя по ID
    const char* GET_USER_ROLE = "SELECT role_id FROM users WHERE id = $1";
    
    // Регистрация нового пользователя (role_id = 2 - обычный пользователь)
    const char* REGISTER_USER = "INSERT INTO users (username, email, password_hash, role_id) VALUES ($1, $2, $3, 2) RETURNING id";
    
    // Вход пользователя (проверка логина и пароля)
    const char* LOGIN_USER = "SELECT id, role_id FROM users WHERE username = $1 AND password_hash = $2";
}

// SQL запросы для работы с разделами
namespace SectionQueries {
    // Получить все разделы
    const char* GET_ALL_SECTIONS = "SELECT id, name, description FROM sections ORDER BY id";
}

// SQL запросы для работы с контентом
namespace ContentQueries {
    // Получить контент по ID раздела
    const char* GET_CONTENT_BY_SECTION = "SELECT id, section_id, title, content_text, created_at, updated_at FROM content WHERE section_id = $1 ORDER BY id";
    
    // Получить весь контент
    const char* GET_ALL_CONTENT = "SELECT id, section_id, title, content_text, created_at, updated_at FROM content ORDER BY id";
    
    // Создать новую запись контента
    const char* CREATE_CONTENT = "INSERT INTO content (section_id, title, content_text, author_id) VALUES ($1, $2, $3, $4) RETURNING id";
    
    // Обновить существующую запись контента
    const char* UPDATE_CONTENT = "UPDATE content SET title = $1, content_text = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3";
    
    // Удалить запись контента
    const char* DELETE_CONTENT = "DELETE FROM content WHERE id = $1";
}

#endif // QUERIES_H

