#!/bin/sh

# @author    Spas Z. Spasov <spas.z.spasov@gmail.com>
# @copyright 2021 Spas Z. Spasov
# @license   https://www.gnu.org/licenses/gpl-3.0.html GNU General Public License, version 3 (or later)

echo 'logrotate --force /etc/logrotate.d/wwwsas-apache2-modsecurity2'
logrotate --force /etc/logrotate.d/wwwsas-apache2-modsecurity2
