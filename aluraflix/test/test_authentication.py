from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from django.contrib.auth import authenticate
from django.urls import reverse
from rest_framework import status

class AuthenticationUserTestCase(APITestCase):
    def setUp(self):
        self.list_url = reverse('programas-list') # programas = basename. -list para a lista de todos os metodos
        self.user = User.objects.create_user('c3po', password='123456')

    def test_autenticacao_de_user_com_credenciais_corretas(self):
        """ Teste para verficiar a autenticação de um User com credenciais corretas """
        user = authenticate(username='c3po', password='123456')
        self.assertTrue((user is not None) and user.is_authenticated)

    def test_requesicao_get_nao_autorizada(self):
        """ Teste que verifica uma requisição get sem autenticação """
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_autenticacao_de_user_com_username_incorreto(self):
        """ Teste que verifica um usuario com o nome incorreto """
        user = authenticate(username='c3pp', password='123456')
        self.assertFalse((user is not None) and user.is_authenticated)

    def test_autenticacao_de_user_com_password_incorreto(self):
        """ Teste que verifica um usuario com o senha incorreto """
        user = authenticate(username='c3po', password='123455')
        self.assertFalse((user is not None) and user.is_authenticated)

    def test_verifica_requisicao_get_user_authenticado(self):
        """ Teste que verifica requisição GET de user autenticado """
        self.client.force_authenticate(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)