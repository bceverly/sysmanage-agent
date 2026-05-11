# $NetBSD$
#
# Phase 11.8 pkgsrc-wip submission stub.  ``DISTNAME`` and
# ``GITHUB_TAG`` are sed-replaced from ``0.0.0`` / ``v0.0.0`` to the
# release tag value by the ``netbsd-pkgsrc`` job in
# build-and-release.yml.  Do not hand-edit on release.

DISTNAME=	sysmanage-agent-0.0.0
CATEGORIES=	sysutils python
MASTER_SITES=	${MASTER_SITE_GITHUB:=bceverly/sysmanage-agent/}
GITHUB_TAG=	v0.0.0
EXTRACT_SUFX=	.tar.gz

MAINTAINER=	bryan@theeverlys.com
HOMEPAGE=	https://github.com/bceverly/sysmanage-agent/
COMMENT=	Cross-platform system management agent for SysManage
LICENSE=	gnu-agpl-v3

WRKSRC=		${WRKDIR}/sysmanage-agent-${PKGVERSION_NOREV}

USE_LANGUAGES=	# none
NO_BUILD=	yes
NO_CONFIGURE=	yes
PKG_DESTDIR_SUPPORT=	user-destdir

DEPENDS+=	${PYPKGPREFIX}-websockets-[0-9]*:../../net/py-websockets
DEPENDS+=	${PYPKGPREFIX}-yaml-[0-9]*:../../textproc/py-yaml
DEPENDS+=	${PYPKGPREFIX}-aiohttp-[0-9]*:../../www/py-aiohttp
DEPENDS+=	${PYPKGPREFIX}-cryptography-[0-9]*:../../security/py-cryptography
DEPENDS+=	${PYPKGPREFIX}-bcrypt-[0-9]*:../../security/py-bcrypt
DEPENDS+=	${PYPKGPREFIX}-psutil-[0-9]*:../../sysutils/py-psutil
DEPENDS+=	${PYPKGPREFIX}-aiofiles-[0-9]*:../../devel/py-aiofiles
DEPENDS+=	${PYPKGPREFIX}-sqlalchemy-[0-9]*:../../databases/py-sqlalchemy
DEPENDS+=	${PYPKGPREFIX}-alembic-[0-9]*:../../databases/py-alembic
DEPENDS+=	${PYPKGPREFIX}-defusedxml-[0-9]*:../../textproc/py-defusedxml

PYTHON_VERSIONS_INCOMPATIBLE=	27

do-install:
	${INSTALL_DATA_DIR} ${DESTDIR}${PREFIX}/libexec/sysmanage-agent
	${INSTALL_SCRIPT} ${WRKSRC}/main.py \
		${DESTDIR}${PREFIX}/libexec/sysmanage-agent/main.py
	${INSTALL_DATA} ${WRKSRC}/alembic.ini \
		${DESTDIR}${PREFIX}/libexec/sysmanage-agent/alembic.ini
	cd ${WRKSRC} && pax -rw src ${DESTDIR}${PREFIX}/libexec/sysmanage-agent/
	${INSTALL_DATA_DIR} ${DESTDIR}${PREFIX}/share/examples/sysmanage-agent
	${INSTALL_DATA} ${WRKSRC}/sysmanage-agent-system.yaml \
		${DESTDIR}${PREFIX}/share/examples/sysmanage-agent/sysmanage-agent.yaml

.include "../../lang/python/application.mk"
.include "../../mk/bsd.pkg.mk"
