import numpy as np

#
# Physical Constants and Units Conversion Factors
#
# Values for these constants, unless otherwise noted, are drawn from IAU,
# IUPAC, NIST, and NASA data, whichever is newer.
# http://maia.usno.navy.mil/NSFA/IAU2009_consts.html
# http://goldbook.iupac.org/list_goldbook_phys_constants_defs.html
# http://physics.nist.gov/cuu/Constants/index.html
# http://nssdc.gsfc.nasa.gov/planetary/factsheet/jupiterfact.html

# Elementary masses
mass_electron_kg = 9.10938291e-31
amu_kg = 1.660538921e-27
amu_grams = amu_kg * 1.0e3
mass_hydrogen_kg = 1.007947 * amu_kg
mass_proton_kg = 1.672623110e-27

# Solar values (see Mamajek 2012)
# https://sites.google.com/site/mamajeksstarnotes/bc-scale
mass_sun_kg = 1.98841586e30
temp_sun_kelvin = 5870.0
luminosity_sun_watts = 3.8270e26

# Consistent with solar abundances used in Cloudy
metallicity_sun = 0.01295

# Conversion Factors:  X au * mpc_per_au = Y mpc
# length
mpc_per_mpc = 1e0
mpc_per_kpc = 1e-3
mpc_per_pc = 1e-6
mpc_per_au = 4.84813682e-12
mpc_per_rsun = 2.253962e-14
mpc_per_rearth = 2.06470307893e-16
mpc_per_rjup = 2.26566120943e-15
mpc_per_miles = 5.21552871e-20
mpc_per_km = 3.24077929e-20
mpc_per_m = 3.24077929e-23
kpc_per_m = mpc_per_m / mpc_per_kpc
pc_per_m = mpc_per_m / mpc_per_pc
km_per_pc = 3.08567758e13
cm_per_pc = 3.08567758e18
cm_per_mpc = 3.08567758e21
km_per_m = 1e-3
km_per_cm = 1e-5
m_per_cm = 1e-2
ly_per_m = 1.05702341e-16
rsun_per_m = 1.4378145e-9
rearth_per_m = 1.56961033e-7  # Mean (volumetric) radius
rjup_per_m = 1.43039006737e-8  # Mean (volumetric) radius
au_per_m = 6.68458712e-12
ang_per_m = 1.0e10

m_per_fpc = 0.0324077929

kpc_per_mpc = 1.0 / mpc_per_kpc
pc_per_mpc = 1.0 / mpc_per_pc
au_per_mpc = 1.0 / mpc_per_au
rsun_per_mpc = 1.0 / mpc_per_rsun
rearth_per_mpc = 1.0 / mpc_per_rearth
rjup_per_mpc = 1.0 / mpc_per_rjup
miles_per_mpc = 1.0 / mpc_per_miles
km_per_mpc = 1.0 / mpc_per_km
m_per_mpc = 1.0 / mpc_per_m
m_per_kpc = 1.0 / kpc_per_m
m_per_km = 1.0 / km_per_m
cm_per_km = 1.0 / km_per_cm
cm_per_m = 1.0 / m_per_cm
pc_per_km = 1.0 / km_per_pc
m_per_pc = 1.0 / pc_per_m
m_per_ly = 1.0 / ly_per_m
m_per_rsun = 1.0 / rsun_per_m
m_per_rearth = 1.0 / rearth_per_m
m_per_rjup = 1.0 / rjup_per_m
m_per_au = 1.0 / au_per_m
m_per_ang = 1.0 / ang_per_m

# time
# "IAU Style Manual" by G.A. Wilkins, Comm. 5, in IAU Transactions XXB (1989)
sec_per_Gyr = 31.5576e15
sec_per_Myr = 31.5576e12
sec_per_kyr = 31.5576e9
sec_per_year = 31.5576e6
sec_per_day = 86400.0
sec_per_hr = 3600.0
sec_per_min = 60.0
day_per_year = 365.25

# velocities, accelerations
speed_of_light_m_per_s = 2.99792458e8
speed_of_light_cm_per_s = speed_of_light_m_per_s * 100.0
standard_gravity_m_per_s2 = 9.80665

# some constants
newton_mks = 6.67408e-11
planck_mks = 6.62606957e-34
# permeability of Free Space
mu_0 = 4.0e-7 * np.pi
# permittivity of Free Space
eps_0 = 1.0 / (speed_of_light_m_per_s ** 2 * mu_0)
avogadros_number = 6.02214085774 * 10 ** 23

# temperature / energy
boltzmann_constant_J_per_K = 1.3806488e-23
erg_per_eV = 1.602176562e-12
J_per_eV = erg_per_eV * 1.0e-7
erg_per_keV = erg_per_eV * 1.0e3
J_per_keV = J_per_eV * 1.0e3
K_per_keV = J_per_keV / boltzmann_constant_J_per_K
keV_per_K = 1.0 / K_per_keV
keV_per_erg = 1.0 / erg_per_keV
eV_per_erg = 1.0 / erg_per_eV
kelvin_per_rankine = 5.0 / 9.0
watt_per_horsepower = 745.69987158227022
erg_per_s_per_watt = 1e7

# Solar System masses
# Standish, E.M. (1995) "Report of the IAU WGAS Sub-Group on Numerical
# Standards", in Highlights of Astronomy (I. Appenzeller, ed.), Table 1,
# Kluwer Academic Publishers, Dordrecht.
# REMARK: following masses include whole systems (planet + moons)
mass_jupiter_kg = mass_sun_kg / 1047.3486
mass_mercury_kg = mass_sun_kg / 6023600.0
mass_venus_kg = mass_sun_kg / 408523.71
mass_earth_kg = mass_sun_kg / 328900.56
mass_mars_kg = mass_sun_kg / 3098708.0
mass_saturn_kg = mass_sun_kg / 3497.898
mass_uranus_kg = mass_sun_kg / 22902.98
mass_neptune_kg = mass_sun_kg / 19412.24

# flux
jansky_mks = 1.0e-26
# Cosmological constants
# Calculated with H = 100 km/s/Mpc, value given in units of h^2 g cm^-3
# Multiply by h^2 to get the critical density in units of g cm^-3
rho_crit_g_cm3_h2 = 1.8788e-29
primordial_H_mass_fraction = 0.76

# Misc. Approximations
mass_mean_atomic_cosmology = 1.22
mass_mean_atomic_galactic = 2.3

# Miscellaneous
HUGE = 1.0e90
TINY = 1.0e-40

# Planck units
hbar_mks = 0.5 * planck_mks / np.pi
planck_mass_kg = np.sqrt(hbar_mks * speed_of_light_m_per_s / newton_mks)
planck_length_m = np.sqrt(hbar_mks * newton_mks / speed_of_light_m_per_s ** 3)
planck_time_s = planck_length_m / speed_of_light_m_per_s
planck_energy_J = planck_mass_kg * speed_of_light_m_per_s * speed_of_light_m_per_s
planck_temperature_K = planck_energy_J / boltzmann_constant_J_per_K
planck_charge_C = np.sqrt(4.0 * np.pi * eps_0 * hbar_mks * speed_of_light_m_per_s)

# Imperial and other non-metric units
kg_per_pound = 0.45359237
pascal_per_atm = 101325.0
m_per_inch = 0.0254
m_per_ft = 0.3048

# logarithmic units
# IEC 60027-3: https://webstore.iec.ch/publication/94
# NIST Special Publication 811: https://www.nist.gov/pml/special-publication-811
neper_per_bel = np.log(10) / 2
