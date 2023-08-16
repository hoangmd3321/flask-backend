from app.app import create_app
from app.settings import DevConfig, ProdConfig, os

# call config service
# CONFIG = DevConfig if os.environ.get('DevConfig') == '1' else ProdConfig
CONFIG = DevConfig

app = create_app(config_object=CONFIG)

if __name__ == '__main__':
    """
    Main Application
    python manage.py
    """
    app.run(debug=True, host='0.0.0.0', port=5012)
