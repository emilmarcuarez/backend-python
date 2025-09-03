from auth import engine
from sqlalchemy import text

def setup_database():
    with engine.connect() as conn:
        print("🔍 Verificando tablas existentes...")
        result = conn.execute(text('SHOW TABLES'))
        tables = [row[0] for row in result]
        print(f"Tablas actuales: {tables}")
        
        # Eliminar tablas existentes si hay problemas
        print("\n🗑️ Eliminando tablas existentes...")
        conn.execute(text("DROP TABLE IF EXISTS reports"))
        conn.execute(text("DROP TABLE IF EXISTS sites"))
        conn.execute(text("DROP TABLE IF EXISTS users"))
        conn.commit()
        
        # Crear tabla users
        print("👤 Creando tabla users...")
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
        
        # Crear tabla sites
        print("🌐 Creando tabla sites...")
        conn.execute(text("""
            CREATE TABLE sites (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                url VARCHAR(512) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_sites_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY unique_user_url (user_id, url)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """))
        
        # Crear tabla reports
        print("📊 Creando tabla reports...")
        conn.execute(text("""
            CREATE TABLE reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                site_id INT NOT NULL,
                score INT NOT NULL,
                report_json LONGTEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_reports_site FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """))
        
        conn.commit()
        
        # Verificar que se crearon correctamente
        print("\n✅ Verificando tablas creadas...")
        result = conn.execute(text('SHOW TABLES'))
        tables = [row[0] for row in result]
        print(f"Tablas finales: {tables}")
        
        if 'users' in tables and 'sites' in tables and 'reports' in tables:
            print("🎉 ¡Base de datos configurada correctamente!")
        else:
            print("❌ Error en la configuración de la base de datos")

if __name__ == "__main__":
    setup_database()
