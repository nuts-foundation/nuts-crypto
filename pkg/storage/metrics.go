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
	"errors"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-crypto/log"
	"github.com/prometheus/client_golang/prometheus"
)

// in minutes
const checkInterval = 15

const label = "period"

// ErrAlreadyStarted is returned when start is called on an already running monitor
var ErrAlreadyStarted = errors.New("certificate monitor already started")

// we register only one
var metric *prometheus.GaugeVec
var mutex sync.Mutex

// CertificateMonitor represents a go procedure which monitors expiring certificates within a given period.
type CertificateMonitor struct {
	exit        chan bool
	period      time.Duration
	periodLabel string
	storage     Storage
}

// DefaultCertificateMonitors returns 3 CertificateMonitors with the following periods: 1 day, 1 week and 4 weeks.
func DefaultCertificateMonitors(storage Storage) []*CertificateMonitor {
	var certMonitors []*CertificateMonitor

	periods := []struct {
		period time.Duration
		label  string
	}{
		{
			time.Hour * 24,
			"day",
		},
		{
			time.Hour * 24 * 7,
			"week",
		},
		{
			time.Hour * 24 * 7 * 4,
			"4_weeks",
		},
	}

	for _, p := range periods {
		m := &CertificateMonitor{
			period:      p.period,
			periodLabel: p.label,
			storage:     storage,
		}
		certMonitors = append(certMonitors, m)
	}

	return certMonitors
}

// Start the certificate monitor for checking expiring certificates between now and the configure period.
func (cm *CertificateMonitor) Start() error {
	err := cm.init()
	if err != nil {
		return err
	}

	if cm.exit != nil {
		return ErrAlreadyStarted
	}

	cm.exit = make(chan bool)
	go cm.loop()

	return nil
}

func (cm *CertificateMonitor) init() error {
	mutex.Lock()
	defer mutex.Unlock()

	var err error

	if metric == nil {
		metric = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "nuts_crypto_certificate_expiry"},
			[]string{label},
		)
		err = prometheus.Register(metric)
	}

	return err
}

// Stop the certificate monitor
func (cm *CertificateMonitor) Stop() {
	cm.exit <- true

	mutex.Lock()
	defer mutex.Unlock()

	if metric != nil {
		prometheus.Unregister(metric)
	}
}

func (cm *CertificateMonitor) loop() {
	for {
		select {
		case _ = <-cm.exit:
			return
		case _ = <-time.After(time.Minute * checkInterval):
			cm.checkExpiry()
		}
	}
}

func (cm CertificateMonitor) checkExpiry() {
	expiringCerts, err := cm.storage.GetExpiringCertificates(time.Now(), time.Now().Add(cm.period))

	if err != nil {
		log.Logger().Error("failed to check expiry:", err)
	}
	l := len(expiringCerts)
	metric.WithLabelValues(cm.periodLabel).Set(float64(l))
}
