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
	errors2 "github.com/pkg/errors"
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
	Period      time.Duration
	PeriodLabel string
	Storage     Storage
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
	expiringCerts, err := cm.Storage.GetExpiringCertificates(time.Now(), time.Now().Add(cm.Period))

	if err != nil {
		log.Logger().Error(errors2.Wrap(err, "failed to check expiry"))
	}
	l := len(expiringCerts)
	metric.WithLabelValues(cm.PeriodLabel).Set(float64(l))
}
