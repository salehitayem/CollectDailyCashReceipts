# Collect Daily Cash Receipts

## Introduction

Welcome to the "Collect Daily Cash Receipts" project! This web application is the culmination of my efforts during the CS50 course, and I'm excited to present it to you. In this README.md file, I'll provide a comprehensive overview of the project, explaining its purpose, the structure of the codebase, and some of the key design choices I made.

## Project Overview

The main objective of this project is to create a user-friendly and secure web application tailored to the needs of accounting and management teams in small to medium-sized retail businesses. The application addresses the common challenges faced by businesses such as supermarkets, coffee shops, and others when it comes to tracking daily cash receipts, sales data, and various payment methods. 

## Project Structure

The project consists of several key files and directories, each serving a specific purpose:

- **app.py**: This is the main Python script that runs the web application using the Flask framework. It handles routing, user authentication, and database interactions.

- **templates/**: This directory contains HTML templates used for rendering web pages. There are templates for the admin, manager, and accounting sections, ensuring a seamless user experience.

- **static/**: This directory stores static assets like CSS stylesheets and JavaScript files to enhance the application's appearance and functionality.

- **helpers.py**: This Python file defines a Flask web application utility that includes a decorator for login authentication (login_required) and a function for rendering apology messages (apology) with special character escaping.

-  **project.db**: This db file contain the database schema . It defines tables for users, stores, sales data, and more

  

## Running the Project on Windows Server 2022

To run this Flask project on a Windows Server 2022 using IIS, follow these steps:

1. **Install Required Software**: Ensure that you have Python installed on your Windows Server. If not, download and install Python from the official website: [Python Downloads](https://www.python.org/downloads/windows/)

2. **Set up a Virtual Environment**: Open a command prompt or PowerShell window with administrative privileges. Navigate to the directory where your Flask project is located and create a virtual environment by running the following command:

   ```bash
   python -m venv venv

3. Install Dependencies: Install the required Python packages from your requirements.txt file:

   ```bash
   pip install -r requirements.txt

4. Configure IIS:

- Open the "Internet Information Services (IIS) Manager" on your Windows Server.
- Create a virtual directory with an alias (e.g., "myflaskapp") and set the physical path to your Flask project directory.
- Download and install the ISAPI_WSGI module from ISAPI_WSGI Downloads.
- Configure the ISAPI_WSGI module in IIS to handle requests for your Flask app. For detailed instructions, refer to the IIS Configuration section below.
 
5. Configure Flask App:

- Create a web.config file in your Flask project directory and configure it with the appropriate settings. Refer to the Flask App Configuration section below for guidance.

6. Restart IIS:

- In the IIS Manager, select the server node in the left-hand pane.
- Click on "Restart" in the Actions pane on the right.

7. Test Your Flask App:

- Open a web browser and navigate to your server's IP address or domain name.

   Your Flask app should now be running through IIS on your Windows Server 2022. If you encounter any issues or error messages, check your configuration and paths for accuracy.

8. IIS Configuration

- Follow these steps to configure IIS:

- Open the IIS Manager.
- Create a virtual directory with an alias (e.g., "myflaskapp") and set the physical path to your Flask project directory.
- Download and install the ISAPI_WSGI module from ISAPI_WSGI Downloads.
- Configure the ISAPI_WSGI module in IIS to handle requests for your Flask app. For detailed instructions, refer to the IIS Configuration section above.

9. Flask App Configuration
- Create a web.config file in your Flask project directory and configure it as follows:
```bash
      <?xml version="1.0" encoding="UTF-8"?>
      <configuration>
          <system.webServer>
              <handlers>
                  <add name="Python via ISAPI_WSGI" path="*" verb="*" modules="IsapiModule" scriptProcessor="C:\path\to\isapi-wsgi.dll" resourceType="Unspecified" requireAccess="Script"/>
              </handlers>
          </system.webServer>
          <appSettings>
              <add key="PYTHONHOME" value="C:\path\to\venv" />
              <add key="WSGIPythonHome" value="C:\path\to\venv" />
              <add key="WSGIPythonPath" value="C:\path\to\your\flask\project;C:\path\to\your\flask\project\venv\Lib\site-packages" />
          </appSettings>
      </configuration>
```
- Replace the paths with the correct paths to your virtual environment and Flask project.



## Running the Project on a Linux Server

1. Install Required Software

- Make sure your Linux server has Python and other necessary tools installed:

  ```bash
  sudo apt update
  sudo apt install python3 python3-venv python3-pip apache2 libapache2-mod-wsgi-py3
2. Set Up a Virtual Environment

- Navigate to the directory where your Flask project is located and create a virtual environment:
  ```bash
  cd /path/to/your/flask/project
  python3 -m venv venv

3. Activate the Virtual Environment

- Activate the virtual environment:

  ```bash
  source venv/bin/activate

4. Install Dependencies

- Install the required Python packages from your requirements.txt file:
  ```bash
  pip install -r requirements.txt

5. Configure Apache

- Create an Apache configuration file for your Flask app. You can create a new file in the /etc/apache2/sites-available/ directory, for example, myflaskapp.conf. Use a text editor to create and edit the file:

  ```bash
  sudo nano /etc/apache2/sites-available/myflaskapp.conf

- Add the following configuration, replacing /path/to/your/flask/project and /path/to/venv with the actual paths to your Flask project and virtual environment:

  ```bash
  <VirtualHost *:80>
    ServerName your_domain_or_server_ip
    ServerAlias www.your_domain_or_server_ip

    DocumentRoot /path/to/your/flask/project

    WSGIDaemonProcess myflaskapp python-path=/path/to/your/flask/project:/path/to/venv/lib/python3.x/site-packages
    WSGIProcessGroup myflaskapp
    WSGIScriptAlias / /path/to/your/flask/project/myflaskapp.wsgi

    <Directory /path/to/your/flask/project>
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
  </VirtualHost>

- Save the file and exit the text editor.

6. Create a WSGI File

- Create a WSGI file for your Flask application. In your project directory, create a file named myflaskapp.wsgi:

  ```bash
  nano /path/to/your/flask/project/myflaskapp.wsgi

- Add the following content, replacing app with the actual name of your Flask application instance:

  ```bash
  #!/usr/bin/python
  import sys
  import logging
  
  logging.basicConfig(stream=sys.stderr)
  sys.path.insert(0, "/path/to/your/flask/project")
  
  from app import app as application

- Save the file and exit the text editor.
  

7.  Enable Your Site

- Enable your Apache site configuration and restart Apache:

  ```bash
  sudo a2ensite myflaskapp.conf
  sudo systemctl restart apache2

8. Set Up Database and Environment Variables

   If your Flask app uses a database or environment variables, make sure to configure them  appropriately. Activate your virtual environment and set the necessary environment variables   in your .env or similar file.

9. Test The  Flask App
  Open a web browser and navigate to your server's IP address or domain name. Your Flask app   should now be running on your Linux server via Apache.

  Please note that these instructions are based on a basic Flask application setup. Depending on the complexity


## To run The Flask project on macOS

1. Set Up a Virtual Environment (Optional/Recommended)
- It's a good practice to use a virtual environment to isolate your project's dependencies. Open Terminal and navigate to your project directory:
  ```bash
     cd /path/to/your/flask/project
- Create a virtual environment and activate it:
  ```bash
  python3 -m venv venv
  source venv/bin/activate

2. Install Dependencies

- If you're using a virtual environment, make sure it's activated (as shown above). Then, install the required Python packages from your requirements.txt file:
  ```bash
  pip install -r requirements.txt

3. Configure Apache
- macOS comes with Apache pre-installed, but it's not enabled by default. You need to create an Apache configuration file for your Flask app.
- Create a new configuration file in the Apache user configuration directory. Replace /path/to/your/flask/project with the actual path to your Flask project directory:
  ```bash
  sudo nano /etc/apache2/users/username.conf

- Add the following configuration to the file, replacing username with your macOS username and /path/to/your/flask/project with the actual path to your Flask project:

  ```bash
  <Directory "/path/to/your/flask/project">
    Options Indexes MultiViews FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
- Save the file and exit the text editor.

4. Create a Virtual Host Configuration
- Create a virtual host configuration file for your Flask app:
  ```bash
  sudo nano /etc/apache2/other/myflaskapp.conf
- Add the following configuration, replacing myflaskapp with a unique name for your app, and /path/to/your/flask/project with the actual path to your Flask project:
  ```bash
  <VirtualHost *:80>
    ServerName localhost
    DocumentRoot "/path/to/your/flask/project"
    WSGIScriptAlias / /path/to/your/flask/project/myflaskapp.wsgi
  </VirtualHost>
- Save the file and exit the text editor.

5. Create a WSGI File
- Create a WSGI file for your Flask application. In your project directory, create a file named myflaskapp.wsgi:
  ```bash
  nano /path/to/your/flask/project/myflaskapp.wsgi
- Add the following content, replacing app with the actual name of your Flask application instance:
  ```bash
  #!/usr/bin/python
  import sys
  import logging
  
  logging.basicConfig(stream=sys.stderr)
  sys.path.insert(0, "/path/to/your/flask/project")
  
  from app import app as application
- Save the file and exit the text editor.

6. Enable Apache and Restart
- Enable Apache and restart it to apply the changes:
  ```bash
  sudo apachectl start

7. Test Your Flask App
  Open a web browser and navigate to http://localhost. Your Flask app should now be running on your macOS system through Apache.

Please note that these instructions are based on a basic Flask application setup. Depending on the complexity of your project, additional configuration may be required. Also, make sure to replace placeholders like /path/to/your/flask/project with the actual paths specific to your project.



## Design Choices
While developing this project, I made certain design choices to ensure its effectiveness and user-friendliness:

- **High Security**: Security is a top priority. User authentication is implemented with robust encryption to safeguard sensitive financial data. Access controls are in place to restrict unauthorized access to certain features.

- **User-Centric Design**: The application is designed with the end-users in mind. It features a clean and intuitive interface to minimize the learning curve for users with varying technical backgrounds.

- **Simplicity**: I opted for a straightforward and minimalistic design to make the application easy to navigate and use. This simplicity enhances the overall user experience and reduces the likelihood of errors.

- **Flexibility**: The application is adaptable to different types of retail businesses. Admins can create and manage stores, cashiers, and users, allowing businesses to tailor the system to their unique needs.

## Conclusion

In conclusion, "Collect Daily Cash Receipts" is a web application designed to streamline financial operations for retail businesses. It prioritizes security, simplicity, and user-friendliness to make the lives of accounting and management teams easier. I hope you find this application valuable, and I encourage you to explore it further to discover its full range of features.

## Project Testing Credentials
- Username: admin
- Password: admin
