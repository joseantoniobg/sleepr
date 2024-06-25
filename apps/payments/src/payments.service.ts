import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientProxy } from '@nestjs/microservices';
import Stripe from 'stripe';
import { NOTIFICATIONS_SERVICE } from '@app/common';
import { PaymentsCreateChargeDto } from './dto/payments-create-charge.dto';

@Injectable()
export class PaymentsService {
  constructor(private readonly configService: ConfigService,
              @Inject(NOTIFICATIONS_SERVICE) private readonly notificationsService: ClientProxy) {}

  private readonly stripeService = new Stripe(this.configService.get('STRIPE_SECRET_KEY'), {
    apiVersion: '2024-04-10',
  });

  async createCharge(data: PaymentsCreateChargeDto) {
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

    this.notificationsService.emit('notify_email', { email: data.email });

    return paymentIntent;
  }
}
