from app import app
if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPS verification
    app.run(debug=True)
