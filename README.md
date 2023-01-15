Aby uruchomić aplikację należy
  
  1. Z poziomu folderu Notesapp/nginx/ wygenerować certyfikaty ssl
  
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ce.key -out ce.crt
    
  2. Z poziomu folderu Notesapp/ uzyć polecenia 
  
    docker-compose up --build
    
   UWAGA
   
   *Nginx jest skonfigurowany na portach 100:80 i 90:443. Aby odpalić aplikację należy podać 127.0.0.1:100 lub 127.0.0.1:90
   
   **Aby działał reset hasła, w pliku Notesapp/project/notesapp/__init__.py należy podać własnego maila i app password. 
   
   Szkielet aplikacji znudowany za pomocą i z wykożystaniem części kodu z tutorialu: https://www.youtube.com/watch?v=MwZwr5Tvyxo&list=PL-osiE80TeTs4UjLw5MM6OjgkjFeUxCYH&ab_channel=CoreySchafer
