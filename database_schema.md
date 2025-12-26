# Схема базы данных

```mermaid
erDiagram
    roles ||--o{ users : has
    sections ||--o{ content : contains
    users ||--o{ content : creates
    
    roles {
        int id PK
        string name UK
    }
    
    users {
        int id PK
        string username UK
        string email UK
        string password_hash
        int role_id FK
        datetime created_at
    }
    
    sections {
        int id PK
        string name
        string description
        datetime created_at
    }
    
    content {
        int id PK
        int section_id FK
        string title
        string content_text
        datetime created_at
        datetime updated_at
        int author_id FK
    }
```

## Описание связей:

- **roles → users**: Один ко многим (ON DELETE RESTRICT)
  - Одна роль может принадлежать многим пользователям
  - Удаление роли запрещено, если есть пользователи с этой ролью

- **sections → content**: Один ко многим (ON DELETE CASCADE)
  - Один раздел может содержать много контента
  - При удалении раздела удаляется весь связанный контент

- **users → content**: Один ко многим (ON DELETE SET NULL)
  - Один пользователь может создать много контента
  - При удалении пользователя author_id устанавливается в NULL

