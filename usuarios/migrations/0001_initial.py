# Generated by Django 4.2 on 2023-04-07 20:58

import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import usuarios.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('perfis', '0001_initial'),
        ('cidades', '0001_initial'),
        ('permissoes', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Usuario',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('telefone', models.CharField(blank=True, max_length=20)),
                ('endereco', models.CharField(blank=True, max_length=100)),
                ('complemento', models.CharField(blank=True, max_length=100)),
                ('cidade', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='usuarios', to='cidades.cidade')),
                ('gropus', models.ManyToManyField(blank=True, db_table='usuarios_perfis', help_text='The profiles this user belongs to. A user will get all permissions granted to each of their profiles.', related_name='user_set', related_query_name='user', to='perfis.perfil', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, db_table='usuarios_permissoes', help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='permissoes.permissao', verbose_name='permissões de usuários')),
            ],
            options={
                'verbose_name': 'Usuário',
                'verbose_name_plural': 'Usuários',
                'db_table': 'usuarios',
                'managed': True,
            },
            managers=[
                ('objects', usuarios.models.UserManager()),
            ],
        ),
    ]