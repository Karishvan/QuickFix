# QuickFix

QuickFix is a comprehensive web application designed to facilitate the efficient reporting, tracking, and visualization of software bugs. It aims to streamline the bug management process for developers and testers through a user-friendly interface. 
The application is built using HTML/CSS frontend, Flask backend, and utilizes matplotlib for generating insightful graphs of bug data/sprint iteration, all while efficiently storing app and user data in a SQL-based database.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributors](#contributors)

## Features

- User Authentication: Secure login and registration system for users using Scrypt password hashing.
- Bug Reporting: Users can report bugs with detailed descriptions.
- Bug Tracking: Users may track sprint-to-sprint statistics and receive email notifications on relevant bugs and/or solved bugs.
- Data Visualization: Utilizes matplotlib to create graphs showing bug trends and statistics.
- Persistent Storage: Utilizes a SQL-based database for storing user and bug data.


## Installation

1. Clone the repository: 
```bash
   git clone https://github.com/Karishvan/QuickFix.git
```
2. Create a virtual environment:
```bash
  python -m venv virt
```
3. Activate virtual environment:
```bash
  source virt/Scripts/activate
```
4. Install dependencies:
```bash
  pip install -r requirements.txt
```
5. Configure environment variables:
```bash
  export EMAIL_USERNAME='your_emaiL@example.com'
  export EMAIL_APPPASS='app password for your email'
  export FLASK_APP='app.py'
```
6. Change SMTP values based on your email service
```python
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
```


## Usage
To run the program, execute
```bash
  flask run
```


## Contributors

- [Ammar Hakim](https://github.com/ammxr)
- [Mohamed Eltaib](https://github.com/RyzenStudios)
- [Karishvan Ragunathan](https://github.com/Karishvan)
- [Nick Shebetun](https://github.com/Nicholas-Shebetun)
- [Burhanuddin Dahodwala](https://github.com/burhan-dahod)



