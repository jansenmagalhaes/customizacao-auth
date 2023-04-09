from django.apps import AppConfig
from django.core import checks
from django.db.models.query_utils import DeferredAttribute
from django.db.models.signals import post_migrate
from django.utils.translation import gettext_lazy as _

from itertools import chain
from django.apps import apps
from django.contrib.auth.checks import check_user_model
from django.contrib.auth.signals import user_logged_in
from django.contrib.contenttypes.management import create_contenttypes
from django.apps import apps as global_apps
from django.db import DEFAULT_DB_ALIAS, router

from . import get_user_model, get_permission_codename


def check_models_permissions(app_configs=None, **kwargs):
    if app_configs is None:
        models = apps.get_models()
    else:
        models = chain.from_iterable(
            app_config.get_models() for app_config in app_configs
        )

    Permission = apps.get_model("permissoes", "Permissao")
    permission_name_max_length = Permission._meta.get_field("name").max_length
    permission_codename_max_length = Permission._meta.get_field("codename").max_length
    errors = []

    for model in models:
        opts = model._meta
        builtin_permissions = dict(_get_builtin_permissions(opts))
        # Check builtin permission name length.
        max_builtin_permission_name_length = (
            max(len(name) for name in builtin_permissions.values())
            if builtin_permissions
            else 0
        )
        if max_builtin_permission_name_length > permission_name_max_length:
            verbose_name_max_length = permission_name_max_length - (
                max_builtin_permission_name_length - len(opts.verbose_name_raw)
            )
            errors.append(
                checks.Error(
                    "The verbose_name of model '%s' must be at most %d "
                    "characters for its builtin permission names to be at "
                    "most %d characters."
                    % (opts.label, verbose_name_max_length, permission_name_max_length),
                    obj=model,
                    id="auth.E007",
                )
            )
        # Check builtin permission codename length.
        max_builtin_permission_codename_length = (
            max(len(codename) for codename in builtin_permissions.keys())
            if builtin_permissions
            else 0
        )
        if max_builtin_permission_codename_length > permission_codename_max_length:
            model_name_max_length = permission_codename_max_length - (
                max_builtin_permission_codename_length - len(opts.model_name)
            )
            errors.append(
                checks.Error(
                    "The name of model '%s' must be at most %d characters "
                    "for its builtin permission codenames to be at most %d "
                    "characters."
                    % (
                        opts.label,
                        model_name_max_length,
                        permission_codename_max_length,
                    ),
                    obj=model,
                    id="auth.E011",
                )
            )
        codenames = set()
        for codename, name in opts.permissions:
            # Check custom permission name length.
            if len(name) > permission_name_max_length:
                errors.append(
                    checks.Error(
                        "The permission named '%s' of model '%s' is longer "
                        "than %d characters."
                        % (
                            name,
                            opts.label,
                            permission_name_max_length,
                        ),
                        obj=model,
                        id="auth.E008",
                    )
                )
            # Check custom permission codename length.
            if len(codename) > permission_codename_max_length:
                errors.append(
                    checks.Error(
                        "The permission codenamed '%s' of model '%s' is "
                        "longer than %d characters."
                        % (
                            codename,
                            opts.label,
                            permission_codename_max_length,
                        ),
                        obj=model,
                        id="auth.E012",
                    )
                )
            # Check custom permissions codename clashing.
            if codename in builtin_permissions:
                errors.append(
                    checks.Error(
                        "The permission codenamed '%s' clashes with a builtin "
                        "permission for model '%s'." % (codename, opts.label),
                        obj=model,
                        id="auth.E005",
                    )
                )
            elif codename in codenames:
                errors.append(
                    checks.Error(
                        "The permission codenamed '%s' is duplicated for "
                        "model '%s'." % (codename, opts.label),
                        obj=model,
                        id="auth.E006",
                    )
                )
            codenames.add(codename)

    return errors

def _get_all_permissions(opts):
    """
    Return (codename, name) for all permissions in the given opts.
    """
    return [*_get_builtin_permissions(opts), *opts.permissions]

def _get_builtin_permissions(opts):
    """
    Return (codename, name) for all autogenerated permissions.
    By default, this is ('add', 'change', 'delete', 'view')
    """
    perms = []
    for action in opts.default_permissions:
        perms.append(
            (
                get_permission_codename(action, opts),
                "Can %s %s" % (action, opts.verbose_name_raw),
            )
        )
    return perms

def create_permissions(
    app_config,
    verbosity=2,
    interactive=True,
    using=DEFAULT_DB_ALIAS,
    apps=global_apps,
    **kwargs,
):
    if not app_config.models_module:
        return

    # Ensure that contenttypes are created for this app. Needed if
    # 'django.contrib.auth' is in INSTALLED_APPS before
    # 'django.contrib.contenttypes'.
    create_contenttypes(
        app_config,
        verbosity=verbosity,
        interactive=interactive,
        using=using,
        apps=apps,
        **kwargs,
    )

    app_label = app_config.label
    try:
        app_config = apps.get_app_config(app_label)
        ContentType = apps.get_model("contenttypes", "ContentType")
        Permission = apps.get_model("permissoes", "Permissao")
    except LookupError:
        return

    if not router.allow_migrate_model(using, Permission):
        return

    # This will hold the permissions we're looking for as
    # (content_type, (codename, name))
    searched_perms = []
    # The codenames and ctypes that should exist.
    ctypes = set()
    for klass in app_config.get_models():
        # Force looking up the content types in the current database
        # before creating foreign keys to them.
        ctype = ContentType.objects.db_manager(using).get_for_model(
            klass, for_concrete_model=False
        )

        ctypes.add(ctype)
        for perm in _get_all_permissions(klass._meta):
            searched_perms.append((ctype, perm))

    # Find all the Permissions that have a content_type for a model we're
    # looking for.  We don't need to check for codenames since we already have
    # a list of the ones we're going to create.
    all_perms = set(
        Permission.objects.using(using)
        .filter(
            content_type__in=ctypes,
        )
        .values_list("content_type", "codename")
    )

    perms = [
        Permission(codename=codename, name=name, content_type=ct)
        for ct, (codename, name) in searched_perms
        if (ct.pk, codename) not in all_perms
    ]
    Permission.objects.using(using).bulk_create(perms)
    if verbosity >= 2:
        for perm in perms:
            print("Adding permission '%s'" % perm)
            
class UsuariosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'usuarios'
    verbose_name = _("Authentication and Authorization")


    def ready(self):
        post_migrate.connect(
            create_permissions,
            dispatch_uid="usuarios.apps.create_permissions",
        )
        last_login_field = getattr(get_user_model(), "last_login", None)
        # Register the handler only if UserModel.last_login is a field.
        if isinstance(last_login_field, DeferredAttribute):
            from usuarios.models import update_last_login

            user_logged_in.connect(update_last_login, dispatch_uid="update_last_login")
        checks.register(check_user_model, checks.Tags.models)
        checks.register(check_models_permissions, checks.Tags.models)
