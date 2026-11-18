INSERT INTO data_sources (
    id,
    name,
    address,
    license_name,
    license_url,
    permitted_use,
    attribution,
    content_policy,
    poll_interval_seconds,
    enabled
) VALUES
    (
        'cert-fr-general',
        'CERT-FR / ANSSI',
        'https://cert.cyber.gouv.fr/feed/',
        'Licence Ouverte 2.0 (Etalab-2.0)',
        'https://cert.cyber.gouv.fr/mentions-legales/',
        'Reuse, including translation and summaries, is permitted under Licence Ouverte 2.0. Do not use the ANSSI logo or imply endorsement. This collector stores only headlines and links.',
        'Source: CERT-FR / ANSSI, Licence Ouverte 2.0 (Etalab). Reuse does not imply ANSSI approval. Legal notice: https://cert.cyber.gouv.fr/mentions-legales/',
        'headline_link',
        3600,
        true
    ),
    (
        'cert-fr-alerts',
        'CERT-FR Alerts',
        'https://cert.cyber.gouv.fr/alerte/feed/',
        'Licence Ouverte 2.0 (Etalab-2.0)',
        'https://cert.cyber.gouv.fr/mentions-legales/',
        'Reuse, including translation and summaries, is permitted under Licence Ouverte 2.0. Do not use the ANSSI logo or imply endorsement. This collector stores only headlines and links.',
        'Source: CERT-FR / ANSSI, Licence Ouverte 2.0 (Etalab). Reuse does not imply ANSSI approval. Legal notice: https://cert.cyber.gouv.fr/mentions-legales/',
        'headline_link',
        3600,
        true
    ),
    (
        'cert-fr-advisories',
        'CERT-FR Advisories',
        'https://cert.cyber.gouv.fr/avis/feed/',
        'Licence Ouverte 2.0 (Etalab-2.0)',
        'https://cert.cyber.gouv.fr/mentions-legales/',
        'Reuse, including translation and summaries, is permitted under Licence Ouverte 2.0. Do not use the ANSSI logo or imply endorsement. This collector stores only headlines and links.',
        'Source: CERT-FR / ANSSI, Licence Ouverte 2.0 (Etalab). Reuse does not imply ANSSI approval. Legal notice: https://cert.cyber.gouv.fr/mentions-legales/',
        'headline_link',
        3600,
        true
    ),
    (
        'cert-fr-cti',
        'CERT-FR CTI',
        'https://cert.cyber.gouv.fr/cti/feed/',
        'Licence Ouverte 2.0 (Etalab-2.0)',
        'https://cert.cyber.gouv.fr/mentions-legales/',
        'Reuse, including translation and summaries, is permitted under Licence Ouverte 2.0. Do not use the ANSSI logo or imply endorsement. This collector stores only headlines and links.',
        'Source: CERT-FR / ANSSI, Licence Ouverte 2.0 (Etalab). Reuse does not imply ANSSI approval. Legal notice: https://cert.cyber.gouv.fr/mentions-legales/',
        'headline_link',
        3600,
        true
    ),
    (
        'cert-fr-ioc',
        'CERT-FR IoC',
        'https://cert.cyber.gouv.fr/ioc/feed/',
        'Licence Ouverte 2.0 (Etalab-2.0)',
        'https://cert.cyber.gouv.fr/mentions-legales/',
        'Reuse, including translation and summaries, is permitted under Licence Ouverte 2.0. Do not use the ANSSI logo or imply endorsement. This collector stores only headlines and links.',
        'Source: CERT-FR / ANSSI, Licence Ouverte 2.0 (Etalab). Reuse does not imply ANSSI approval. Legal notice: https://cert.cyber.gouv.fr/mentions-legales/',
        'headline_link',
        3600,
        true
    )
ON CONFLICT (id) DO NOTHING;
