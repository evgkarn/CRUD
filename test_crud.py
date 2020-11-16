"""
test crud
"""
import unittest
import json
import datetime
import requests


class LoginTestCase(unittest.TestCase):
    """
    test base function
    """

    def login(self, email, password):
        """
        :param email: email user
        :param password: password user
        :return: token
        """
        info = {"email": email, "password": password}
        return requests.post("http://127.0.0.1:5000/api-token-auth/",
                             data=json.dumps(info),
                             headers={'Content-Type': 'application/json'})

    def test_login(self):
        """
        test login user
        """
        lo_gin = self.login('admin@admin.com', 'admin')
        assert lo_gin.json()['token'] is not None
        lo_gin = self.login('admin@admin.com', '123456')
        assert lo_gin.json()['error'] == 'Unauthorized access'
        lo_gin = self.login('adminawd', 'defaultx')
        assert lo_gin.json()['error'] == 'Unknown user'

    def create_user(self, **kwargs):
        """
        test create user with params
        :param kwargs: field user
        :return: json fields created user
        """
        return requests.post("http://127.0.0.1:5000/api/v1/users/", data=json.dumps(kwargs),
                             headers={'Content-Type': 'application/json'})

    def update_user(self, user_id, **kwargs):
        """
        Update user fields
        :param user_id: id user for update
        :param kwargs: json fields for update
        :return: json fields update user
        """
        return requests.put("http://127.0.0.1:5000/api/v1/users/%s/" % user_id,
                            data=json.dumps(kwargs),
                            headers={'Content-Type': 'application/json'})

    def delete_user(self, user_id, **kwargs):
        """
        Delete user
        :param user_id: id user for delete
        :param kwargs: token
        :return: True if True
        """
        return requests.delete("http://127.0.0.1:5000/api/v1/users/%s/" % user_id,
                               data=json.dumps(kwargs),
                               headers={'Content-Type': 'application/json'})

    def test_create_update_delete(self):
        """
        main test
        """
        new_email = datetime.datetime.now().strftime("%y%m%d-%H%M%S%f") + "@admin.com"
        password = '123456'
        cre_ate = self.create_user(email=new_email,
                                   password=password,
                                   role=0,
                                   active=1,
                                   first_name='',
                                   last_name='')
        assert cre_ate.json()['email'] == new_email

        lo_gin = self.login(new_email, password)
        token = lo_gin.json()['token']
        user_id = cre_ate.json()['id']
        up_date = self.update_user(user_id,
                                   token=token,
                                   email=new_email,
                                   password='new_password',
                                   role=0, active=0,
                                   first_name='new_first_name',
                                   last_name='new_last_name')
        assert up_date.json()['first_name'] == 'new_first_name'
        assert up_date.json()['last_name'] == 'new_last_name'
        assert up_date.json()['active'] == 0

        del_ete = self.delete_user(user_id, token=token)
        assert del_ete.json()['result'] is True

        del_ete = self.delete_user(user_id, token='incorrect_token')
        assert del_ete.json()['message'] == 'Token is invalid!'


if __name__ == '__main__':
    unittest.main()
