from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from .models import Info, Profile

class VaultTestCase(TestCase):
    def setUp(self):
        self.username = 'testuser'
        self.password = 'testpassword'
        self.user = User.objects.create_user(username=self.username, password=self.password)
        self.profile = Profile.objects.create(user=self.user)
        self.info = Info.objects.create(user_account=self.user, website_name='example.com', username='testuser', website_password='testpassword')

    def test_index_view(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'vault/index.html')

    def test_account_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('account'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'vault/account.html')

    def test_vault_unlock_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.post(reverse('vault_unlock'), {'master_password': 'testpassword'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('vault'))

    def test_vault_lock_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.post(reverse('vault_lock'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('vault'))

    def test_vault_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('vault'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'vault/vault.html')

    def test_login_view(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'vault/login.html')

    def test_signup_view(self):
        response = self.client.get(reverse('signup'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'vault/signup.html')

    def test_logout_view(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))

    def test_copy_password_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('copy_password', args=[self.info.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('vault'))

    def test_edit_password_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.post(reverse('edit_password', args=[self.info.pk]), {
            'website_name': 'example.com',
            'username': 'newuser',
            'website_password': 'newpassword'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('vault'))

    def test_delete_password_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('delete_password', args=[self.info.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('vault'))
