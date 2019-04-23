import os
import unittest
from userservice import  app, db
from userservice.models import Registreduser, Group, Role



TEST_DB = 'test.db'
basedir = os.path.abspath(os.path.dirname(__file__))

class BasicTests(unittest.TestCase):
    """A base test case."""

    ############################
    #### setup and teardown ####
    ############################

    # executed prior to each test
    def setUp(self):

        # ensure that db URI is set up correctly

        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +os.path.join(basedir, TEST_DB)
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
        self.app = app.test_client()

        # ensure that db create models

        db.create_all()
        db.session.add(Registreduser("aicha", "abd", "ad@min.com", "56997000", "aicha22", "03/15/2019", True))
        db.session.add(Group("Test group", "03/23/2019", "This is a test. Only a test."))
        db.session.add(Role("Visitor"))
        db.session.commit()

        # Disable sending emails during unit testing
        #mail.init_app(app)
        #self.assertEqual(app.debug, False)

    # executed after each test

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    ###############
    #### tests ####
    ###############

    #def test_main_page(self):
     #   response = self.app.get('/', follow_redirects=True)
      #  self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()