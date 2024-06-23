import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Payload } from '@nestjs/microservices';
import Stripe from 'stripe';
import { CreateChargeDto } from '@app/common';

@Injectable()
export class PaymentsService {
  constructor(private readonly configService: ConfigService) {}

  private readonly stripeService = new Stripe(this.configService.get('STRIPE_SECRET_KEY'), {
    apiVersion: '2024-04-10',
  });

  async createCharge(data: CreateChargeDto) {
    const paymentMethod = await this.stripeService.paymentMethods.create({
      type: 'card',
      card: {
        token: 'tok_visa'
      },
    });

    const paymentIntent = await this.stripeService.paymentIntents.create({
      payment_method: paymentMethod.id,
      amount: data.amount * 100,
      confirm: true,
      payment_method_types: ['card'],
      currency: 'usd',
    });

    return paymentIntent;
  }
}
