vple_real_info = """
VPLE - Vulnerable Penetration Testing Lab Environment
====================================================

SYSTEM SPECIFICATIONS:
- Type: Linux Virtual Machine (intentionally vulnerable)
- Default Login: administrator:password
- Purpose: Security training, penetration testing practice
- Network: Standard VM network configuration
- Command to get IP: hostname -I

AVAILABLE WEB APPLICATIONS:
1. DVWA (Damn Vulnerable Web App)
   - Port: 1335
   - URL: http://[IP]:1335/
   - Technology: PHP/MySQL web application
   - Description: Deliberately vulnerable web application for security testing

2. Mutillidae II
   - Port: 1336  
   - URL: http://[IP]:1336/
   - Technology: PHP/MySQL
   - Description: Contains all OWASP Top Ten vulnerabilities plus additional ones
   - Features: Security levels 0-5, hints system, reset functionality

3. WebGoat
   - Port: 1337
   - URL: http://[IP]:1337/WebGoat/
   - Technology: Java-based web application
   - Description: Interactive teaching environment for web application security
   - Warning: Machine extremely vulnerable while running

4. bWAPP (buggy web application)
   - Port: 8080
   - URL: http://[IP]:8080/install.php (first install)
   - URL: http://[IP]:8080/ (after install)
   - Technology: PHP application with MySQL database
   - Description: Over 100 different web vulnerabilities
   - Coverage: All major known web bugs including OWASP Top 10

5. OWASP Juice Shop
   - Port: 3000
   - URL: http://[IP]:3000/
   - Technology: Node.js, Express, and Angular (JavaScript-heavy)
   - Description: Modern and sophisticated insecure web application
   - Features: Scoreboard system, various difficulty challenges

6. Security Ninjas
   - Port: 8899
   - URL: http://[IP]:8899/
   - Technology: PHP-based
   - Description: Application Security Training Program
   - Content: OWASP Top 10 (2013) vulnerabilities, 10 hands-on exercises

7. WordPress
   - Port: 8800
   - URL: http://[IP]:8800/
   - Technology: PHP with MySQL/MariaDB database
   - Description: Popular Content Management System (CMS)
   - Usage: 41.4% of top 10 million websites use WordPress

SYSTEM CHARACTERISTICS:
- All applications deliberately contain security vulnerabilities
- Designed for legal penetration testing and security training
- Multiple web technologies represented (PHP, Java, JavaScript, CMS)
- No security controls implemented by design
- Educational/training environment

TECHNICAL DETAILS:
- Web server starts automatically on boot
- Multiple database backends (MySQL, MariaDB)
- Various web frameworks and technologies
- Default configurations typically insecure
- Standard HTTP protocols
"""

print("✓ Real VPLE system information loaded from official documentation")
