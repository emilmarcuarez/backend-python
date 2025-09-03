from auth import engine
from sqlalchemy import text

with engine.connect() as conn:
    # Verificar tablas existentes
    result = conn.execute(text('SHOW TABLES'))
    tables = [row[0] for row in result]
    print(f"Tablas existentes: {tables}")
    
    # Si no existe la tabla users, crearla
    if 'users' not in tables:
        print("❌ Tabla users no existe, creándola...")
        conn.execute(text("""
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """))
        conn.commit()
        print("✅ Tabla users creada")
    
    # Verificar estructura de users
    result = conn.execute(text('DESCRIBE users'))
    print("\nEstructura de tabla users:")
    for row in result:
        print(f"  {row[0]} - {row[1]} - {row[2]}")
    
    print("\n🎉 Base de datos verificada correctamente")
