# $OpenBSD$

COMMENT =		lightweight system monitoring agent for SysManage

GH_ACCOUNT =		bceverly
GH_PROJECT =		sysmanage-agent
GH_TAGNAME =		v0.0.0  # Auto-updated by make installer
REVISION =		0

CATEGORIES =		sysutils

HOMEPAGE =		https://sysmanage.org

MAINTAINER =		Your Name <your.email@example.com>

# AGPLv3
PERMIT_PACKAGE =	Yes

MODULES =		lang/python

MODPY_VERSION =		${MODPY_DEFAULT_VERSION_3}

RUN_DEPENDS =		net/py-websockets${MODPY_FLAVOR} \
			textproc/py-yaml${MODPY_FLAVOR} \
			www/py-aiohttp${MODPY_FLAVOR} \
			security/py-cryptography${MODPY_FLAVOR} \
			databases/py-sqlalchemy${MODPY_FLAVOR} \
			databases/py-alembic${MODPY_FLAVOR}

NO_BUILD =		Yes
NO_TEST =		Yes

# Installation directories
SUBST_VARS +=		SYSCONFDIR LOCALSTATEDIR

# User and group for the daemon
SYSMANAGE_USER =	_sysmanage
SYSMANAGE_GROUP =	_sysmanage

do-install:
	${INSTALL_DATA_DIR} ${PREFIX}/libexec/sysmanage-agent
	${INSTALL_SCRIPT} ${WRKSRC}/main.py ${PREFIX}/libexec/sysmanage-agent/
	test -d ${WRKSRC}/src && \
		cp -R ${WRKSRC}/src ${PREFIX}/libexec/sysmanage-agent/ || true
	test -f ${WRKSRC}/alembic.ini && \
		${INSTALL_DATA} ${WRKSRC}/alembic.ini ${PREFIX}/libexec/sysmanage-agent/ || true
	test -d ${WRKSRC}/alembic && \
		cp -R ${WRKSRC}/alembic ${PREFIX}/libexec/sysmanage-agent/ || true
	test -d ${WRKSRC}/database && \
		cp -R ${WRKSRC}/database ${PREFIX}/libexec/sysmanage-agent/ || true
	test -d ${WRKSRC}/i18n && \
		cp -R ${WRKSRC}/i18n ${PREFIX}/libexec/sysmanage-agent/ || true
	test -d ${WRKSRC}/security && \
		cp -R ${WRKSRC}/security ${PREFIX}/libexec/sysmanage-agent/ || true
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/sysmanage-agent
	test -f ${WRKSRC}/sysmanage-agent.yaml && \
		${INSTALL_DATA} ${WRKSRC}/sysmanage-agent.yaml \
			${PREFIX}/share/examples/sysmanage-agent/sysmanage-agent.yaml || true
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/sysmanage-agent
	${INSTALL_DATA} ${WRKSRC}/README.md ${PREFIX}/share/doc/sysmanage-agent/
	test -f ${WRKSRC}/LICENSE && \
		${INSTALL_DATA} ${WRKSRC}/LICENSE ${PREFIX}/share/doc/sysmanage-agent/ || true
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/sysmanage-agent/sbom
	test -f ${WRKSRC}/sbom/sysmanage-agent-sbom.json && \
		${INSTALL_DATA} ${WRKSRC}/sbom/sysmanage-agent-sbom.json \
			${PREFIX}/share/doc/sysmanage-agent/sbom/ || true
	${INSTALL_DATA_DIR} ${DESTDIR}/etc/rc.d
	${INSTALL_SCRIPT} ${FILESDIR}/sysmanage_agent.rc \
		${DESTDIR}/etc/rc.d/sysmanage_agent

.include <bsd.port.mk>
