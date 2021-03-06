# -*- coding: utf-8 -*-
# Copyright 2014 Telefonica Investigación y Desarrollo, S.A.U
#
# This file is part of FI-WARE project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For those usages not covered by the Apache version 2.0 License please
# contact with opensource@tid.es

__author__ = 'henar'

from xml.etree.ElementTree import Element, SubElement


class Tier:
    def __init__(self, tier_name, tier_num_min='1', tier_num_max='1', tier_num_initial='1',
                 tier_image='694ae405-0731-4dab-a50f-d089d1cca04d',
                 tier_flavour='2', tier_keypair='', tier_floatingip='false' ):
        self.name = tier_name
        self.tier_num_min = tier_num_min
        self.tier_num_max = tier_num_max
        self.tier_num_initial = tier_num_initial
        self.tier_image = tier_image
        self.tier_flavour = tier_flavour
        self.tier_keypair = tier_keypair
        self.tier_floatingip = tier_floatingip
        self.products = []
        self.networks = []

    def add_product(self, product):
        self.products.append(product)

    def add_network(self, network):
        self.networks.append(network)


    def delete_product(self, product):
        self.products.pop(product)

    def to_tier_xml(self):
        tier_dtos = Element("tierDto")
        min_num_inst = SubElement(tier_dtos, "minimumNumberInstances")
        min_num_inst.text = self.tier_num_min
        ini_num_inst = SubElement(tier_dtos, "initialNumberInstances")
        ini_num_inst.text = self.tier_num_initial
        max_mum_inst = SubElement(tier_dtos, "maximumNumberInstances")
        max_mum_inst.text = self.tier_num_max
        name_tier = SubElement(tier_dtos, "name")
        name_tier.text = self.name
        image_tier = SubElement(tier_dtos, "image")
        image_tier.text = self.tier_image
        flavour_tier = SubElement(tier_dtos, "flavour")
        flavour_tier.text = self.tier_flavour
        keypair = SubElement(tier_dtos, "keypair")
        keypair.text = self.tier_keypair
        floating_ip = SubElement(tier_dtos, "floatingip")
        floating_ip.text = self.tier_floatingip

        if self.products:
            for product in self.products:
                prod = product.to_product_xml_env()

                tier_dtos.append(prod)

        if self.networks:
            for net in self.networks:
                prod = net.to__xml()

                tier_dtos.append(prod)
        return tier_dtos

    def to_xml(self):
        tier_dtos = Element("tierDtos")
        min_num_inst = SubElement(tier_dtos, "minimumNumberInstances")
        min_num_inst.text = self.tier_num_min
        ini_num_inst = SubElement(tier_dtos, "initialNumberInstances")
        ini_num_inst.text = self.tier_num_initial
        max_mum_inst = SubElement(tier_dtos, "maximumNumberInstances")
        max_mum_inst.text = self.tier_num_max
        name_tier = SubElement(tier_dtos, "name")
        name_tier.text = self.name
        image_tier = SubElement(tier_dtos, "image")
        image_tier.text = self.tier_image
        flavour_tier = SubElement(tier_dtos, "flavour")
        flavour_tier.text = self.tier_flavour
        keypair = SubElement(tier_dtos, "keypair")
        keypair.text = self.tier_keypair
        floating_ip = SubElement(tier_dtos, "floatingip")
        floating_ip.text = self.tier_floatingip

        if self.products:
            for product in self.products:
                prod = product.to_product_xml_env()

                tier_dtos.append(prod)
        return tier_dtos


