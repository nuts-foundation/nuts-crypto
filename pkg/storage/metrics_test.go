/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestCertificateMonitor_Start(t *testing.T) {
	fs := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("Starting a monitor twice returns an error", func(t *testing.T) {
		m := CertificateMonitor{
			period:      time.Hour,
			periodLabel: "hour",
			storage:     fs,
		}

		err := m.Start()
		defer m.Stop()

		assert.NoError(t, err)
		err = m.Start()
		assert.Error(t, err)
	})

	t.Run("Registering multiple monitors results in a single GaugeVec registered with prometheus", func(t *testing.T) {
		m := CertificateMonitor{
			period:      time.Hour,
			periodLabel: "hour",
			storage:     fs,
		}

		m2 := CertificateMonitor{
			period:      time.Hour * 2,
			periodLabel: "two_hour",
			storage:     fs,
		}

		err := m.Start()
		defer m.Stop()

		assert.NoError(t, err)

		err = m2.Start()
		defer m2.Stop()

		assert.NoError(t, err)
	})
}

func TestCertificateMonitor_init(t *testing.T) {
	metric = nil
	fs := createTempStorage(t.Name())
	defer emptyTemp(t.Name())
	m := CertificateMonitor{
		period:      time.Hour,
		periodLabel: "hour",
		storage:     fs,
	}

	t.Run("Calling init registers the metric with prometheus", func(t *testing.T) {
		m.init()

		assert.NotNil(t, metric)
	})
}

func TestCertificateMonitor_checkExpiry(t *testing.T) {
	fs := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	m := CertificateMonitor{
		period:      time.Hour * 48,
		periodLabel: "within_2_days",
		storage:     fs,
	}
	m.init()

	t.Run("checkexpiry calls set on metric", func(t *testing.T) {
		m.checkExpiry()

		metrics, _ := prometheus.DefaultGatherer.Gather()
		for _, mf := range metrics {
			if *mf.Name == "nuts_crypto_certificate_expiry" {
				assert.Equal(t, 1, len(mf.Metric))
			}
		}
	})

	t.Run("checkexpiry calls set on metric", func(t *testing.T) {
		m.checkExpiry()

		metrics, _ := prometheus.DefaultGatherer.Gather()
		for _, mf := range metrics {
			if *mf.Name == "nuts_crypto_certificate_expiry" {
				assert.Equal(t, float64(0), *mf.Metric[0].Gauge.Value)
			}
		}
	})

	t.Run("expiring certificate is count", func(t *testing.T) {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		asn1 := test.GenerateCertificateEx(time.Now(), 1, rsaKey)
		fs.SaveCertificate(types.KeyForEntity(types.LegalEntity{URI: "test"}), asn1)

		m.checkExpiry()
		metrics, _ := prometheus.DefaultGatherer.Gather()
		for _, mf := range metrics {
			if *mf.Name == "nuts_crypto_certificate_expiry" {
				assert.Equal(t, float64(1), *mf.Metric[0].Gauge.Value)
				mf.Reset()
			}
		}
	})
}

func TestDefaultCertificateMonitors(t *testing.T) {
	fs := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("it returns three monitors", func(t *testing.T) {
		certMonitors := DefaultCertificateMonitors(fs)

		assert.Len(t, certMonitors, 3)
		assert.Equal(t, "day", certMonitors[0].periodLabel)
		assert.Equal(t, "week", certMonitors[1].periodLabel)
		assert.Equal(t, "4_weeks", certMonitors[2].periodLabel)
	})
}
