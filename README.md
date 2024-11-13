## S3 Browser

A web-based interface for managing and viewing Amazon S3 buckets and their contents with user authentication, role-based access control, and permissions management.

Features
--------

-   **User Authentication**: Login/logout with role-based access control.
-   **Admin Dashboard**: Admins can create users and assign bucket permissions.
-   **Bucket and Object Viewer**: View S3 buckets and objects with search and pagination.
-   **Download Links**: Generates signed URLs for object downloads.

Getting Started
---------------

### Prerequisites

-   **Python**: Version 3.x
-   **pip**: Package installer for Python
-   **AWS Credentials**: Must have permission to access the S3 service and assume roles

### Installation

1.  **Clone the Repository**:

    ```bash
    git clone https://github.com/stwins60/s3-browser.git
    cd flask-s3-browser
    ```

2.  **Set Up a Virtual Environment**:

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use: venv\Scripts\activate`
    ```

3.  **Install Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables**: Create a `.env` file in the project root with:

    ```plaintext
    SECRET_KEY=your-secret-key
    AWS_REGION=us-east-1
    PORT=5000  # Optional: default is 5000
    IAM_ROLE= # Optional: IAM role to assume
    ```

5.  **Initialize the Database**:

    Run the application to set up the SQLite database and create the admin user.

    ```bash
    python app.py
    ```

6.  **Create the Session Directory** (if not already created):

    ```bash
    mkdir browser_session
    ```

### Usage

1.  **Run the Application**:

    ```bash
    python app.py
    ```

2.  **Access the Interface**: Visit `http://localhost:5000` in your browser.

3.  **Admin Login**:

    -   Use the username "admin" and the password defined in the `add_admin_user` function in `app.py`.
    -   Navigate to `/admin` to add users and set permissions.

API Routes
----------

-   **`/`**: Redirects to the login page.
-   **`/login`**: User login page.
-   **`/logout`**: Logs out the current user.
-   **`/admin`**: Admin page for creating users and managing permissions (Admin only).
-   **`/buckets`**: List of accessible buckets.
-   **`/buckets/<bucket_name>/objects`**: Lists objects within a specific bucket.
-   **`/buckets/<bucket_name>/download/<object_key>`**: Generates a signed URL to download an object from the specified bucket.

Permissions
-----------

-   **Admin**: Full access to user and bucket permissions.
-   **User**: View access to assigned buckets only.

Security
--------

-   **Environment Variables**: Store sensitive information in the `.env` file.
-   **CSRF Protection**: Ensures forms are protected from CSRF attacks using Flask-WTF.

License
-------

This project is licensed under the MIT License. See the LICENSE file for details.