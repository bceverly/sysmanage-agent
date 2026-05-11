# $OpenBSD$
#
# Phase 11.8 ports-tree submission stub.  ``GH_TAGNAME`` is sed-replaced
# from ``v0.0.0`` to the release tag value by the ``openbsd-ports`` job
# in build-and-release.yml.  Do not hand-edit on release.

COMMENT =		cross-platform system management agent for SysManage

GH_ACCOUNT =		bceverly
GH_PROJECT =		sysmanage-agent
GH_TAGNAME =		v0.0.0
REVISION =		0

CATEGORIES =		sysutils

HOMEPAGE =		https://github.com/bceverly/sysmanage-agent

MAINTAINER =		Bryan Everly <bryan@theeverlys.com>

# AGPLv3+
PERMIT_PACKAGE =	Yes

MODULES =		lang/python

RUN_DEPENDS =		net/py-websockets${MODPY_FLAVOR} \
			textproc/py-yaml${MODPY_FLAVOR} \
			www/py-aiohttp${MODPY_FLAVOR} \
			security/py-cryptography${MODPY_FLAVOR} \
			security/py-bcrypt${MODPY_FLAVOR} \
			sysutils/py-psutil${MODPY_FLAVOR} \
			devel/py-aiofiles${MODPY_FLAVOR} \
			databases/py-sqlalchemy${MODPY_FLAVOR} \
			databases/py-alembic${MODPY_FLAVOR} \
			textproc/py-defusedxml${MODPY_FLAVOR}

NO_BUILD =		Yes
NO_TEST =		Yes
PKG_ARCH =		*

SUBST_VARS +=		SYSCONFDIR LOCALSTATEDIR

do-install:
	${INSTALL_DATA_DIR} ${PREFIX}/libexec/sysmanage-agent
	${INSTALL_SCRIPT} ${WRKSRC}/main.py ${PREFIX}/libexec/sysmanage-agent/
	${INSTALL_DATA} ${WRKSRC}/alembic.ini ${PREFIX}/libexec/sysmanage-agent/
	cp -R ${WRKSRC}/src ${PREFIX}/libexec/sysmanage-agent/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/sysmanage-agent
	${INSTALL_DATA} ${WRKSRC}/sysmanage-agent-system.yaml \
		${PREFIX}/share/examples/sysmanage-agent/sysmanage-agent.yaml
	${INSTALL_DATA_DIR} ${DESTDIR}/etc/rc.d
	${INSTALL_SCRIPT} ${FILESDIR}/sysmanage-agent.rc \
		${DESTDIR}/etc/rc.d/sysmanage_agent

.include <bsd.port.mk>
