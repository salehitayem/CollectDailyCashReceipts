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

- **database.py**: This Python script manages the database schema and interactions. It defines tables for users, stores, sales data, and more.

- **security.py**: This script focuses on security measures, including user authentication and access control. It ensures that only authorized users can access specific features and data.

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
